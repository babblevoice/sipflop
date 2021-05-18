# sipflop

SIP/RTP testing utilities.

This is not designed to be anything fancy - but enough to run some simple tests for diagnosis
or verification. Included is enough to generate a SIP dialog and then generate RTP data as required.

Rename config_template.json to config.json and modify as appropriate.

## Tests

### delayechotest

Measure the round trip time of RTP data through a target host/system using an echo application on the server.
