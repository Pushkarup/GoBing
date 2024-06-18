# GoBing
![image](https://github.com/Pushkarup/GoBing/assets/148672587/294d14ef-b0a8-48e4-ac70-d3f9ec9b1ec7)

## Overview

The GoBing Tool is designed to perform web searches using Bing to find URLs that may be vulnerable to SQL injection or other vulnerabilities. It operates fully proxyless and is an open-source project intended for educational purposes only. Please use this tool responsibly and ethically.

## Features

- Performs web searches using Bing to find potential vulnerabilities.
- Operates fully proxyless.
- Supports concurrent searches with configurable settings.
- Filters out unwanted links based on a predefined list of forbidden words.
- Removes duplicate entries from the results.
- Uses colored console output for better readability.

## Installation

To get started with the Bing Dork Search Tool, follow these steps:

1. **Clone the repository:**

    ```sh
    git clone https://github.com/Pushkarup/GoBing.git
    cd GoBing
    ```

2. **Install dependencies:**

    Ensure you have [Go](https://golang.org/dl/) installed. Then, run:

    ```sh
    go mod download
    ```

3. **Create a `settings.ini` file:**

    Create a file named `settings.ini` in the root directory with the following content:

    ```ini
    [settings]
    threads = 100
    timeout = 60
    MaxIdleConns = 200
    MaxIdleConnsPerHost = 20
    ```

## Usage

1. **Prepare a dorks file:**

    Create a file containing your search dorks, one per line. For example, `dorks.txt`:

    ```text
    inurl:admin.php
    inurl:login.asp
    ```

2. **Run the tool:**

    Execute the tool by running:

    ```sh
    go run bing.go
    ```

    Follow the prompts to enter the dorks file name and the number of pages to search (maximum 15 pages).

## Contributing

Contributions to improve and enhance the project are welcome. To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or suggestions, please contact Pushkar Upadhyay.
thepushkar24@gmail.com

