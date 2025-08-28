# NetSpy
NetSpy is a tool for collecting network traffic data on a server using eBPF.  
**Note:** This project is currently in the planning stage and is not yet implemented.

## Planned Features

- Minimal impact on server performance.
- Flexible traffic filtering configuration.
- Secure and efficient data collection at the kernel level.

## How It Will Work

1. **Data Collection:** An eBPF program in the Linux kernel will intercept network events and collect relevant traffic data.
2. **Daemon:** A dedicated daemon written in C will extract this data from the kernel.
3. **Client Delivery:** The collected information will be sent to a client for further analysis.

## Requirements (planned)

- Linux with eBPF support.
- C compiler (e.g., gcc).
- Administrator privileges to load eBPF programs.

## Installation (planned)

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/netspy.git
    ```
2. Build the daemon:
    ```sh
    cd netspy
    make
    ```
3. Run the daemon with administrator privileges:
    ```sh
    sudo ./netspy-daemon
    ```