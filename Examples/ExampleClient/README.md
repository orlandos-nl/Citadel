1. Build the dockerfile using `docker build --file ExampleServer.dockerfile --tag sshd-example .`
2. Run the docker image using `docker run -p 2323:22 sshd-example`
3. Run this Swift code to connect tom the server and run a command using `swift run`