# opentok-websocket

Creates two-way websocket connection between a opentok session and a third-party websocket service.

We use libuwsc for adding websocket support to our application. You can download the source from https://github.com/zhaojh329/libuwsc and build it.

1. Please check the opentok linux samples repo for instructions on installing Opentok Linux SDK (https://github.com/opentok/opentok-linux-sdk-samples/tree/main/Basic-Video-Chat)
2. cd src/build
3. generate Makefile by executing "CC=clang CXX=clang++ cmake .."
4. Build the application by executing "make"
5. you should see vonage-rti-connector binary in build folder

## running the app

vonage-rti-connector expects a number of command-line arguments in the following order

1. apikey
2. sessionid
3. token
4. websocket end-point url
5. publisher-name (this is the only stream we subscribe to)

## How it works

1. launch the app by executing "./vonage-rti-connector [api-key] [session-id] [token] [websocket-url] [publisher-name]"
2. This app will connect to a opentok session with give credentials
3. connect to the websocket url provided
4. subscribe to the stream whos publisher name matches the one provided on command-line
5. send initial JSON payload to the websocket end-point {"uid":"xyz123","sampling_rate":"16000"}
6. send audio received from the subscriber to the websocket.
7. received audio from websocket, buffer it and send it in real-time to the opentok session. Name of the publisher is [publisher-name]_rti
8. receive json payload from websocket and send it to opentok session using signal (with prefix "rti")
9. app will kill itself if either the publisher we are monitoring has left the session or the websocket has closed.

