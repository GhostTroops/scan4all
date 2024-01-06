# new features
- 1 allows the configured commands to be run distributedly on the remote server, and the results are received and processed uniformly.
- 2 Allows configuring specified commands to use specified agents when running. It is not recommended to use agents for nmap and masscan.
- 3、The execution of each target + command will check the index library and skip it if it exists. Multiple iterations will also perform repeated checks to avoid repeated executions.
- 