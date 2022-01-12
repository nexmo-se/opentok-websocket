#include <opentok.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <signal.h>
#include <fcntl.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h> 

#include "otk_thread.h"
#include "uwsc.h"
#include "circular_buffer.h"

#define CIRCULAR_BUFFER_SIZE 15351808
#define NUM_SAMPLES_PER_FRAME 160

int sampling_rate = 16000;

static std::atomic<bool> g_is_connected(false);
static std::atomic<bool> g_is_publishing(false);
static otc_publisher *g_publisher = nullptr;

otc_session *session = nullptr;
CircularBuffer cbuf;
struct uwsc_client *cl;
struct ev_loop *loop = EV_DEFAULT;
struct ev_signal signal_watcher;
int ping_interval = 10;	/* second */
char uid[256];
char publisher_name[260];

struct audio_device {
  otc_audio_device_callbacks audio_device_callbacks;
  otk_thread_t renderer_thread;
  std::atomic<bool> renderer_thread_exit;
  otk_thread_t capturer_thread;
  std::atomic<bool> capturer_thread_exit;
};
static otk_thread_func_return_type capturer_thread_start_function(void *arg) {
  struct audio_device *device = static_cast<struct audio_device *>(arg);
  if (device == nullptr) {
    otk_thread_func_return_value;
  }

  while (device->capturer_thread_exit.load() == false) {
	int16_t samples[NUM_SAMPLES_PER_FRAME];
	int actual = CircularBufferPop(cbuf,NUM_SAMPLES_PER_FRAME*2,&samples[0]);
	if(actual > 0){
		otc_audio_device_write_capture_data(samples, actual/2);
	}
	usleep(10*1000);
  }
  otk_thread_func_return_value;
}
static otk_thread_func_return_type renderer_thread_start_function(void *arg) {
  struct audio_device *device = static_cast<struct audio_device *>(arg);
  if (device == nullptr) {
    otk_thread_func_return_value;
  }

  while (device->renderer_thread_exit.load() == false) {
  	int16_t samples[NUM_SAMPLES_PER_FRAME];

	size_t actual = otc_audio_device_read_render_data(samples,NUM_SAMPLES_PER_FRAME);

	if(actual > 0){
		cl->send(cl,(const void*)samples,actual*sizeof(int16_t),UWSC_OP_BINARY);
	}
	usleep(10*1000);
  }
  std::cout << "while loop exited" << std::endl;

  otk_thread_func_return_value;
}

static otc_bool audio_device_destroy_renderer(const otc_audio_device *audio_device,
                                              void *user_data) {
  struct audio_device *device = static_cast<struct audio_device *>(user_data);
  if (device == nullptr) {
    return OTC_FALSE;
  }

  device->renderer_thread_exit = true;
  otk_thread_join(device->renderer_thread);

  return OTC_TRUE;
}
static otc_bool audio_device_destroy_capturer(const otc_audio_device *audio_device,
                                              void *user_data) {
  struct audio_device *device = static_cast<struct audio_device *>(user_data);
  if (device == nullptr) {
    return OTC_FALSE;
  }

  device->capturer_thread_exit = true;
  otk_thread_join(device->capturer_thread);

  return OTC_TRUE;
}
static otc_bool audio_device_start_renderer(const otc_audio_device *audio_device,
                                            void *user_data) {
  struct audio_device *device = static_cast<struct audio_device *>(user_data);
  printf("Starting audio renderer\n");
  if (device == nullptr) {
    return OTC_FALSE;
  }

  device->renderer_thread_exit = false;
  if (otk_thread_create(&(device->renderer_thread), &renderer_thread_start_function, (void *)device) != 0) {
    return OTC_FALSE;
  }
  printf("Started audio renderer\n");

  return OTC_TRUE;
}
static otc_bool audio_device_start_capturer(const otc_audio_device *audio_device,
                                            void *user_data) {
  struct audio_device *device = static_cast<struct audio_device *>(user_data);
  printf("Starting audio capturer\n");
  if (device == nullptr) {
    return OTC_FALSE;
  }

  device->capturer_thread_exit = false;
  if (otk_thread_create(&(device->capturer_thread), &capturer_thread_start_function, (void *)device) != 0) {
    return OTC_FALSE;
  }
  printf("Started audio capturer\n");

  return OTC_TRUE;
}
static otc_bool audio_device_get_render_settings(const otc_audio_device *audio_device,
                                                  void *user_data,
                                                  struct otc_audio_device_settings *settings) {
  if (settings == nullptr) {
    return OTC_FALSE;
  }

  settings->number_of_channels = 1;
  settings->sampling_rate = sampling_rate;
  return OTC_TRUE;
}
static otc_bool audio_device_get_capturer_settings(const otc_audio_device *audio_device,
                                                  void *user_data,
                                                  struct otc_audio_device_settings *settings) {
  if (settings == nullptr) {
    return OTC_FALSE;
  }

  settings->number_of_channels = 1;
  settings->sampling_rate = sampling_rate;
  return OTC_TRUE;
}

otc_bool should_subscribe(const otc_stream * stream){
	if(strlen(uid) == 0)
		return OTC_TRUE;
	/* we can either decide based on publisher name or connection data */
	const char * name = otc_stream_get_name(stream);
	if(name != NULL && strcmp(uid,name)==0){
		return OTC_TRUE;
	}
	else{
		return OTC_FALSE;
	}

	/* if you want to use connection data, comment above */
	const otc_connection *conn = otc_stream_get_connection(stream);
	const char * data = otc_connection_get_data(conn);
	if(strcmp(uid,data)==0){
		return OTC_TRUE;
	}
	else{
		return OTC_FALSE;
	}
	return OTC_FALSE;
}

static void on_subscriber_connected(otc_subscriber *subscriber,
                                    void *user_data,
                                    const otc_stream *stream) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  otc_subscriber_set_subscribe_to_video(subscriber,0);
}

static void on_subscriber_render_frame(otc_subscriber *subscriber,
                                       void *user_data,
                                       const otc_video_frame *frame) {
}

static void on_subscriber_error(otc_subscriber* subscriber,
                                void *user_data,
                                const char* error_string,
                                enum otc_subscriber_error_code error) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  std::cout << "Subscriber error. Error code: " << error_string << std::endl;
}

static void on_session_connected(otc_session *session, void *user_data) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  g_is_connected = true;
  if ((session != nullptr) && (g_publisher != nullptr)) {
    if (otc_session_publish(session, g_publisher) == OTC_SUCCESS) {
      std::cout <<  "Publishing successfully" << std::endl;
      g_is_publishing = true;
      return;
    }
    std::cout << "Could not publish successfully" << std::endl;
  }

}

static void on_session_connection_created(otc_session *session,
                                          void *user_data,
                                          const otc_connection *connection) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
}

static void on_session_connection_dropped(otc_session *session,
                                          void *user_data,
                                          const otc_connection *connection) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
}

static void on_session_stream_received(otc_session *session,
                                       void *user_data,
                                       const otc_stream *stream) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  if(should_subscribe(stream) == OTC_FALSE){
	  return;
  }
  struct otc_subscriber_callbacks subscriber_callbacks = {0};
  subscriber_callbacks.user_data = user_data;
  subscriber_callbacks.on_connected = on_subscriber_connected;
  subscriber_callbacks.on_render_frame = on_subscriber_render_frame;
  subscriber_callbacks.on_error = on_subscriber_error;

  otc_subscriber *subscriber = otc_subscriber_new(stream,&subscriber_callbacks);
  otc_subscriber_set_subscribe_to_video(subscriber,0);
 
  if (otc_session_subscribe(session, subscriber) == OTC_SUCCESS) {
    printf("subscribed successfully\n");
    return;
  }
  else{
    printf("Error during subscribe\n");
  }
}

static void on_session_stream_dropped(otc_session *session,
                                      void *user_data,
                                      const otc_stream *stream) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  if(should_subscribe(stream) == OTC_FALSE){
	  return;
  }
  /* the stream we are monitoring has dropped, kill the app */
  exit(-1);
}

static void on_session_disconnected(otc_session *session, void *user_data) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
}

static void on_session_error(otc_session *session,
                             void *user_data,
                             const char *error_string,
                             enum otc_session_error_code error) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  std::cout << "Session error. Error : " << error_string << std::endl;
}
static void on_publisher_stream_created(otc_publisher *publisher,
                                        void *user_data,
                                        const otc_stream *stream) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
}
static void on_publisher_render_frame(otc_publisher *publisher,
                                      void *user_data,
                                      const otc_video_frame *frame) {
}
static void on_publisher_stream_destroyed(otc_publisher *publisher,
                                          void *user_data,
                                          const otc_stream *stream) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
}
static void on_publisher_error(otc_publisher *publisher,
                               void *user_data,
                               const char* error_string,
                               enum otc_publisher_error_code error_code) {
  std::cout << __FUNCTION__ << " callback function" << std::endl;
  std::cout << "Publisher error. Error code: " << error_string << std::endl;
}
static void on_otc_log_message(const char* message) {
  std::cout <<  __FUNCTION__ << ":" << message << std::endl;
}

void sigfun(int sig)
{
        printf("You have presses Ctrl-C , please press again to exit\n");
	(void) signal(SIGINT, SIG_DFL);
}
static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    if (w->signum == SIGINT) {
        ev_break(loop, EVBREAK_ALL);
        printf("Normal quit\n");
    }
}

/** websocket handlers - start **/
static void uwsc_onopen(struct uwsc_client *cl)
{
    static struct ev_io stdin_watcher;
    char payload[512];
    const char * json = "{\"uid\":\"%s\",\"sampling_rate\":\"%d\"}"; 
    memset(payload,'\0',512);
    sprintf(payload,json,uid,sampling_rate);
    cl->send(cl,(void*)payload,strlen(payload),UWSC_OP_TEXT);
    printf("onopen\n");
}

static void uwsc_onmessage(struct uwsc_client *cl,
    void *data, size_t len, bool binary)
{
    printf("Recv:");

    if (binary) {
        int16_t *p = (int16_t*)data;
	CircularBufferPush(cbuf,p,len);
    } else {
	otc_session_send_signal(session,"rti",(const char*)data);
        printf("[%.*s]\n", (int)len, (char *)data);
    }

}

static void uwsc_onerror(struct uwsc_client *cl, int err, const char *msg)
{
    printf("onerror:%d: %s\n", err, msg);
    ev_break(cl->loop, EVBREAK_ALL);
}

static void uwsc_onclose(struct uwsc_client *cl, int code, const char *reason)
{
    printf("onclose:%d: %s\n", code, reason);
    ev_break(cl->loop, EVBREAK_ALL);
    /* websocket closed, exit the app */

    exit(-1);
}

/** websocket handlers - end **/

int main(int argc, char** argv) {
  char* apiKey;
  char* sessionId;
  char* token;
  char* ws_url;
  
  std::cout << "API KEY: " << argv[1] << std::endl;
  std::cout << "SESSION ID: " << argv[2] << std::endl;
  std::cout << "TOKEN: " << argv[3] << std::endl;
  std::cout << "WS_URL: " << argv[4] << std::endl;
  std::cout << "UID: " << argv[5] << std::endl;
  
  apiKey = argv[1];
  sessionId = argv[2];
  token = argv[3];
  ws_url = argv[4];
  memset(uid,'\0',256);
  if(argv[5] != NULL)
  	strncpy(uid,argv[5],strlen(argv[5]));
  cbuf = CircularBufferCreate(CIRCULAR_BUFFER_SIZE);
  
  if (otc_init(nullptr) != OTC_SUCCESS) {
    std::cout << "Could not init OpenTok library" << std::endl;
    return EXIT_FAILURE;
  }
#ifdef CONSOLE_LOGGING
  otc_log_set_logger_callback(on_otc_log_message);
  otc_log_enable(OTC_LOG_LEVEL_ALL);
#endif

  struct audio_device *device = (struct audio_device *)malloc(sizeof(struct audio_device));
  device->audio_device_callbacks = {0};
  device->audio_device_callbacks.user_data = static_cast<void *>(device);
  device->audio_device_callbacks.destroy_renderer = audio_device_destroy_renderer;
  device->audio_device_callbacks.start_renderer = audio_device_start_renderer;
  device->audio_device_callbacks.get_render_settings = audio_device_get_render_settings;
  device->audio_device_callbacks.get_capture_settings = audio_device_get_capturer_settings;
  device->audio_device_callbacks.destroy_capturer = audio_device_destroy_capturer;
  device->audio_device_callbacks.start_capturer = audio_device_start_capturer;
  otc_set_audio_device(&(device->audio_device_callbacks));
  
  struct otc_session_callbacks session_callbacks = {0};
  session_callbacks.on_connected = on_session_connected;
  session_callbacks.on_connection_created = on_session_connection_created;
  session_callbacks.on_connection_dropped = on_session_connection_dropped;
  session_callbacks.on_stream_received = on_session_stream_received;
  session_callbacks.on_stream_dropped = on_session_stream_dropped;
  session_callbacks.on_disconnected = on_session_disconnected;
  session_callbacks.on_error = on_session_error;

  session = otc_session_new(apiKey, sessionId, &session_callbacks);

  if (session == nullptr) {
    std::cout << "Could not create OpenTok session successfully" << std::endl;
    return EXIT_FAILURE;
  }

  struct otc_publisher_callbacks publisher_callbacks = {0};
  publisher_callbacks.user_data = NULL;
  publisher_callbacks.on_stream_created = on_publisher_stream_created;
  publisher_callbacks.on_render_frame = on_publisher_render_frame;
  publisher_callbacks.on_stream_destroyed = on_publisher_stream_destroyed;
  publisher_callbacks.on_error = on_publisher_error;

  struct otc_publisher_settings * pub_settings = otc_publisher_settings_new();
  otc_publisher_settings_set_video_track(pub_settings, OTC_FALSE);
  /* publisher name is <uid>_rti */
  memset(publisher_name,'\0',260);
  sprintf(publisher_name,"%s_rti",uid);
  otc_publisher_settings_set_name(pub_settings,publisher_name);
  g_publisher = otc_publisher_new_with_settings( &publisher_callbacks,pub_settings);
  
  if (g_publisher == nullptr) {
    std::cout << "Could not create OpenTok publisher successfully" << std::endl;
    otc_session_delete(session);
    return EXIT_FAILURE;
  }
  otc_session_connect(session, token);

  cl = uwsc_new(loop, ws_url, ping_interval, NULL);
  cl->onopen = uwsc_onopen;
  cl->onmessage = uwsc_onmessage;
  cl->onerror = uwsc_onerror;
  cl->onclose = uwsc_onclose;
  ev_signal_init(&signal_watcher, signal_cb, SIGINT);
  ev_signal_start(loop, &signal_watcher);

  ev_run(loop, 0);
  free(cl);

  if ((session != nullptr) && g_is_connected.load()) {
    otc_session_disconnect(session);
  }

  if (session != nullptr) {
    otc_session_delete(session);
  }

  if (device != nullptr) {
    free(device);
  }

  otc_destroy();

  return EXIT_SUCCESS;
}
