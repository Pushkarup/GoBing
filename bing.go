/*
Disclaimer:
This project is authored by Pushkar Upadhyay and is intended for educational purposes only.
The code searches for dorks in Bing and retrieves URLs that may be vulnerable to SQL injection or other vulnerabilities.
Please use this tool responsibly and ethically. The code operates fully proxyless and is an open-source project.
Contributions to improve and enhance the project are welcome and encouraged.
*/

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	random "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"gopkg.in/ini.v1"

	"golang.org/x/sync/semaphore"
)

type Foreground struct {
	Black      string
	Red        string
	Green      string
	Yellow     string
	Blue       string
	LightGreen string
	LightBlue  string
}

// Setting FOREGROUND values
var Fore = Foreground{
	Red:        "\033[31m",
	Green:      "\033[32m",
	Yellow:     "\033[33m",
	Blue:       "\033[34m",
	LightGreen: "\033[92m",
	LightBlue:  "\033[94m",
}

type Styling struct {
	Bold      string
	Dim       string
	Reset_all string
}

var Style = Styling{
	Bold:      "\033[1m",
	Dim:       "\033[2m",
	Reset_all: "\033[0m",
}

var (
	forbiddenWords = []string{
		"bing", "wikipedia", "stackoverflow", "amazon", "google",
		"microsoft", "youtube", "reddit", "quora", "telegram", "msdn",
		"facebook", "apple", "twitter", "instagram", "cracked", "nulled",
		"yahoo", "gbhackers", "github", "sourceforge", "aol", "yandex",
		"ask", "papago", "naver",
	}
	sema   *semaphore.Weighted
	client *http.Client
)

//============================================================================================================================
/*
init initializes the global settings and HTTP client configuration from a configuration file.
It reads the settings from a `settings.ini` file and configures a semaphore and an HTTP client with specified parameters.

The function performs the following steps:
1. Loads the configuration from `settings.ini`.
2. Reads the number of threads, timeout, maximum idle connections, and maximum idle connections per host from the configuration file.
3. Initializes a semaphore to limit concurrency based on the number of threads.
4. Configures an HTTP client with the specified timeout and connection settings.

Parameters:
  - None (this is an init function and runs automatically at program startup).

Returns:
  - None (any errors encountered will cause the program to exit).

Dependencies:
  - ini: A package for reading and writing INI files.
  - semaphore: A package for controlling concurrency with weighted semaphores.
  - Fore and Style: Variables for colored console output.
  - sema: A global semaphore variable.
  - client: A global HTTP client variable.

Configuration File (`settings.ini`):
  The `settings.ini` file should contain the following structure:

[settings]
threads = 100
timeout = 60
MaxIdleConns = 200
MaxIdleConnsPerHost = 20


Example:
Place the `settings.ini` file in the same directory as the executable. The program will read this file during initialization and configure the semaphore and HTTP client accordingly.

Error Handling:
- If the `settings.ini` file cannot be read, the function prints an error message and exits the program.

Note:
- The function uses colored console output for error messages.
- The HTTP client is configured to disable compression and support only HTTP/1.1.

*/

func init() {
	cfg, err := ini.Load("settings.ini")
	if err != nil {
		fmt.Printf(" %s[ERROR]%s       | Failed to read settings.ini: %v\n", Fore.Red, Style.Reset_all, err)
		os.Exit(1)
	}

	threads := cfg.Section("settings").Key("threads").MustInt(100)
	timeout := cfg.Section("settings").Key("timeout").MustInt(60)
	MaxIdleConns := cfg.Section("settings").Key("MaxIdleConns").MustInt(200)
	MaxIdleConnsPerHost := cfg.Section("settings").Key("MaxIdleConnsPerHost").MustInt(20)

	sema = semaphore.NewWeighted(int64(threads))
	client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        MaxIdleConns,
			IdleConnTimeout:     time.Duration(timeout) * time.Second,
			DisableCompression:  true,
			MaxIdleConnsPerHost: MaxIdleConnsPerHost,
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"http/1.1"},
			},
		},
	}
}

//============================================================================================================================
/*
containsForbiddenWords checks if a given link contains any forbidden words.
The function iterates over a predefined list of forbidden words and checks if any of these words are present in the link.

Parameters:
  - link: A string representing the URL to be checked.

Returns:
  - bool: Returns true if the link contains any forbidden words, false otherwise.

Dependencies:
  - forbiddenWords: A predefined list of strings that represent forbidden words.

Steps:
  1. Iterates over the list of forbidden words.
  2. Checks if each forbidden word is contained in the link.
  3. Returns true if any forbidden word is found, otherwise returns false.

Note:
  - The function uses the strings.Contains method to check for the presence of each forbidden word.
  - This function is case-sensitive; "Spam" and "spam" are considered different words.

*/

func containsForbiddenWords(link string) bool {
	for _, word := range forbiddenWords {
		if strings.Contains(link, word) {
			return true
		}
	}
	return false
}

//============================================================================================================================
/*
bing performs a web search using Bing and processes the results.
It constructs a Bing search URL, sends a GET request, extracts links from the response, and writes them to a file.
The function includes error handling and retries the request up to 3 times if a timeout occurs.

Parameters:
  - ctx: A context.Context to handle cancellation and timeouts for the HTTP request.
  - search: A string representing the search query.
  - count: An integer specifying the number of search results to retrieve.
  - wg: A pointer to a sync.WaitGroup to signal when the function is done.

Dependencies:
  - sema: A semaphore to limit concurrent access.
  - random: A source of randomness for generating the page load time parameter.
  - generateRandomCVID: A function to generate a random CVID for the request.
  - uarand: A package to generate random User-Agent strings.
  - client: An HTTP client to send the request.
  - Fore and Style: Variables for colored console output.
  - containsForbiddenWords: A function to filter out undesirable links.

Example:
  var wg sync.WaitGroup
  ctx := context.Background()
  wg.Add(1)
  go bing(ctx, "golang concurrency", 10, &wg)
  wg.Wait()

Steps:
  1. Acquires a semaphore to control concurrency.
  2. Constructs the Bing search URL with the encoded search query.
  3. Retries the HTTP request up to 3 times in case of a timeout.
  4. Sends the HTTP GET request with a random User-Agent header.
  5. Checks the response status and reads the response body.
  6. Extracts links from the response body using a regular expression.
  7. Filters and writes the links to a file.

Error Handling:
  - Prints detailed error messages for various stages (acquiring semaphore, creating request, sending request, reading response, writing to file).
  - Handles context cancellation and request timeouts gracefully.
  - Continues to the next retry on timeout errors.

Note:
  - The function uses colored console output for different types of messages (errors, timeouts, found links).
  - Extracted links are filtered to avoid specific patterns and avoid forbidden words.

Concurrency:
  - The function uses a semaphore to limit the number of concurrent searches.
  - The sync.WaitGroup ensures the caller can wait for the function to complete.

*/

func bing(ctx context.Context, search string, count int, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := sema.Acquire(ctx, 1); err != nil {
		fmt.Printf("Failed to acquire semaphore: %v\n", err)
		return
	}
	defer sema.Release(1)

	encodedSearch := url.QueryEscape(search)
	url := fmt.Sprintf("http://www.bing.com/search?pglt=%d&q=%s&first=%d&cvid=%s", random.Intn(90)+10, encodedSearch, count, generateRandomCVID())

	for i := 1; i < 4; i++ { // Retry up to 3 times
		if ctx.Err() != nil {
			fmt.Printf(" %s[ERROR]%s       | context canceled\n", Fore.Red, Style.Reset_all)
			return
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			fmt.Printf(" %s[ERROR]%s       | creating request: %v\n", Fore.Red, Style.Reset_all, err)
			return
		}

		req.Header.Set("User-Agent", uarand.GetRandom())

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Printf(" %s[ERROR]%s       | context canceled during request\n", Fore.Red, Style.Reset_all)
				return
			}
			if err, ok := err.(net.Error); ok && err.Timeout() {
				fmt.Printf(" %s[TIMEOUT]%s     | Request timed out, retrying... (%d/3)\n", Fore.Yellow, Style.Reset_all, i)
				continue
			}
			fmt.Printf(" %s[HTTP ERROR]%s  | error occurred: %v\n", Fore.Red, Style.Reset_all, err)
			return
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Printf(" %s[HTTP ERROR]%s  | occurred: %s\n", Fore.Red, Style.Reset_all, resp.Status)
			resp.Body.Close()
			return
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if ctx.Err() != nil {
				fmt.Printf(" %s[ERROR]%s       | context canceled while reading body\n", Fore.Red, Style.Reset_all)
				return
			}
			fmt.Printf(" %s[ERROR]%s       | reading response body: %v\n", Fore.Red, Style.Reset_all, err)
			continue
		}

		re := regexp.MustCompile(`<h2><a href="(.+?)"`)
		matches := re.FindAllStringSubmatch(string(body), -1)
		for _, match := range matches {
			link := match[1]
			if strings.Contains(link, "?") && strings.Contains(link, "=") && !containsForbiddenWords(link) {
				if !strings.Contains(link, "http://bs.yandex.ru") {
					fmt.Printf(" %s[FOUND]%s       | %s\n", Fore.Green, Style.Reset_all, link)
					file, err := os.OpenFile("found.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
					if err != nil {
						fmt.Printf(" %s[ERROR]%s       | opening file: %v\n", Fore.Red, Style.Reset_all, err)
						return
					}
					defer file.Close()
					_, err = file.WriteString(link + "\n")
					if err != nil {
						fmt.Printf(" %s[ERROR]%s       | writing to file: %v\n", Fore.Red, Style.Reset_all, err)
						return
					}
				}
			}
		}
		break
	}
}

//============================================================================================================================
/*
generateRandomCVID generates a random CVID (Client Version ID) as a hexadecimal string.
The function creates a 16-byte array, fills it with random bytes, and then encodes it into a hexadecimal string.

Parameters:
  - None

Returns:
  - string: A random 32-character hexadecimal string representing the CVID. Returns an empty string if an error occurs while generating random bytes.

Dependencies:
  - rand: A package for generating cryptographically secure random numbers.
  - hex: A package for encoding and decoding hexadecimal strings.

Example:
  cvid := generateRandomCVID()
  fmt.Println("Generated CVID:", cvid)

Steps:
  1. Creates a 16-byte array.
  2. Fills the array with random bytes using `rand.Read`.
  3. Encodes the byte array into a hexadecimal string.
  4. Returns the hexadecimal string.

Error Handling:
  - If an error occurs while generating random bytes, the function returns an empty string.

Note:
  - The function uses the `crypto/rand` package to ensure the generated bytes are cryptographically secure.
  - The resulting CVID is a 32-character string because each byte is represented by two hexadecimal characters.

*/

func generateRandomCVID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	randomHex := hex.EncodeToString(bytes)

	cvid := randomHex

	return cvid
}

//============================================================================================================================
/*
removeDuplicates removes duplicate lines from a file specified by the provided file path.
The function reads all lines from the file, removes duplicates, and writes the unique lines back to the same file.

Parameters:
  - filepath: A string representing the path to the file to be processed.

Returns:
  - error: An error if the function fails at any step (opening the file, reading lines, writing lines, etc.), or nil if successful.

Example:
  err := removeDuplicates("path/to/your/file.txt")
  if err != nil {
    log.Fatalf("Failed to remove duplicates: %v", err)
  }

Steps:
  1. Opens the specified file for reading.
  2. Reads all lines from the file and stores unique lines in a map.
  3. Reopens the file for writing (truncating it in the process).
  4. Writes the unique lines back to the file.
  5. Flushes the writer to ensure all data is written to the file.

Error Handling:
  - Returns a formatted error message for each step where an error might occur (opening, reading, creating, writing, and flushing the file).

Note:
  - The function uses a map with empty struct values to store unique lines, ensuring constant-time checks for duplicates.
  - The use of `defer` ensures that files are properly closed after their operations are complete.

Dependencies:
  - The function relies on the `os`, `bufio`, and `fmt` packages from the Go standard library.
*/
func removeDuplicates(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()
	uniqueLines := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		uniqueLines[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf(" %s[ERROR]%s       | reading file: %v", Fore.Red, Style.Reset_all, err)
	}
	file, err = os.Create(filepath)
	if err != nil {
		return fmt.Errorf(" %s[ERROR]%s       | could not create file: %v", Fore.Red, Style.Reset_all, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for line := range uniqueLines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf(" %s[ERROR]%s       | writing to file: %v", Fore.Red, Style.Reset_all, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf(" %s[ERROR]%s       | flushing writer: %v", Fore.Red, Style.Reset_all, err)
	}
	return nil
}

//============================================================================================================================
/*
fileLen calculates the number of lines in a given file.
The function opens the specified file, reads it line by line, and counts the total number of lines.

Parameters:
  - filePath: A string representing the path to the file.

Returns:
  - int: The total number of lines in the file. Returns 0 if the file cannot be opened.

Dependencies:
  - os: A package for interacting with the operating system.
  - bufio: A package for buffered I/O.

Example:
  lineCount := fileLen("example.txt")
  fmt.Printf("The file contains %d lines\n", lineCount)

Steps:
  1. Opens the specified file.
  2. Creates a new scanner to read the file line by line.
  3. Increments the line count for each line read by the scanner.
  4. Returns the total number of lines.

Error Handling:
  - The function does not handle errors explicitly; it returns 0 if the file cannot be opened. Consider adding error handling to improve robustness.

Note:
  - The function uses the `defer` keyword to ensure the file is closed after the operation is complete.
  - Error handling is minimal; improving error handling by checking and reporting errors is recommended for production code.

*/

func fileLen(filePath string) int {
	file, _ := os.Open(filePath)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}
	return lineCount
}

//============================================================================================================================
/*
clearConsole clears the console screen.
The function executes the appropriate command to clear the console screen on Windows systems.

Parameters:
  - None

Returns:
  - None

Dependencies:
  - exec: A package for running external commands.
  - os: A package for interacting with the operating system.

Example:
  clearConsole()

Steps:
  1. Creates a new command to execute the `cls` command on Windows using the `cmd` shell.
  2. Sets the standard output of the command to the current process's standard output.
  3. Runs the command to clear the console screen.

Note:
  - This function is designed for Windows systems. For Unix-based systems (Linux, macOS), use `exec.Command("clear")` instead.
  - The function does not handle errors. Consider adding error handling for robustness.

*/

func clearConsole() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

//============================================================================================================================
/*
logo prints a stylized logo to the console using ANSI color codes.
The function uses formatted strings to create an ASCII art logo with colored text.

Parameters:
  - None

Returns:
  - None

Dependencies:
  - fmt: A package for formatted I/O.
  - Fore: A package or object for ANSI foreground color codes.
  - Style: A package or object for ANSI style codes.

Example:
  logo()

Steps:
  1. Uses the `fmt.Printf` function to print each line of the logo.
  2. Applies ANSI color and style codes to create a colorful and bold ASCII art logo.

Note:
  - This function assumes the presence of predefined ANSI color and style codes in `Fore` and `Style`.

*/
func logo() {
	fmt.Printf("")
	fmt.Printf("")
	fmt.Printf("")
	fmt.Printf(" %s░                                                                             ░%s\n", Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf("                                     %s        █▀▀█ ▀█▀  █▄  █  █▀▀█              \n%s", Style.Bold+Fore.Yellow, Style.Reset_all)
	fmt.Printf(" %s░ ▄▓▒▀▄                           %s          █▀▀▄  █   █ █ █  █ ▄▄             %s░%s\n", Style.Bold+Fore.LightBlue, Fore.Yellow, Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf(" %s ▐▓███░▓▄▓▄ ▀▀░  ▀■ ▓▄▄▄▓▄ ▄▄ ▄ ▓▄%s          █▄▄█ ▄█▄  █  ▀█  █▄▄█              \n%s", Style.Bold+Fore.LightBlue, Fore.Yellow, Style.Reset_all)
	fmt.Printf(" %s▌ %s▓░█▓▓▀ ▀%s▄  ▀▀▀  ▄   %s▀▓░▄ ░  ▓▀▀ ▀▀▀▓ ░                                      %s▒\n%s", Style.Bold+Fore.Green, Style.Bold+Fore.LightBlue, Style.Bold+Fore.Green, Style.Bold+Fore.LightBlue, Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf(" %s█▄ %s▀▀▀ %s▄▀            ▀▄   ▄▄    ▄▄              ▄▄▄▄                  ▄▄▄   ▄▄█\n%s", Style.Bold+Fore.Green, Style.Bold+Fore.LightBlue, Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf(" %s▓░█▓██░▓▌     %sparser%s  ▐█▀▀▀▓██▀▀▀░███▓██▀████▀▀▀▀░▓████▓██████▓▀▀▀▓▀▀▀▓███▓▀██▓%s\n", Style.Bold+Fore.Green, Fore.Yellow, Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf(" %s░▀ ▀ ▓▀░▌             ▐▓▀  ░ ▀▀▓█▀ ▀▀       ▀▓▀   ▀▀▄▄█▓▀▓▀          ▓▀▓▀▀   ▀█%s\n", Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf(" %s▓    ░  ▀■ ▓▄      ▄▄■▀                               ▀▌                      ▐%s\n", Style.Bold+Fore.Green, Style.Reset_all)
	fmt.Printf(" %s░          ░   ▀▓▀          BY PUSHKAR UPADHYAY        ▀                      █%s\n", Style.Bold+Fore.Green, Style.Reset_all)
}

//============================================================================================================================
/*
main is the entry point of the program.
It performs the following tasks:
1. Clears the console and displays a logo.
2. Prompts the user to enter the name of a file containing search dorks.
3. Reads the search dorks from the specified file.
4. Prompts the user to enter the number of pages to search (with a maximum of 15 pages).
5. Performs concurrent Bing searches for each dork and each page.
6. Removes duplicate entries from the result file.
7. Prints the total number of unique results found.
8. Indicates the completion of the search.

Parameters:
  - None

Returns:
  - None

Dependencies:
  - fmt: A package for formatted I/O.
  - os: A package for interacting with the operating system.
  - bufio: A package for buffered I/O.
  - sync: A package for synchronization.
  - context: A package for managing context with cancellation.
  - strconv: A package for string conversions.
  - strings: A package for string manipulation.
  - clearConsole: A function to clear the console screen.
  - logo: A function to display a stylized logo.
  - bing: A function to perform Bing searches.
  - removeDuplicates: A function to remove duplicate lines from a file.
  - fileLen: A function to count the number of lines in a file.

Example:
  Run the program and follow the prompts to enter the dorks file name and the number of pages to search.

Steps:
  1. Clears the console using the `clearConsole` function.
  2. Displays the logo using the `logo` function.
  3. Prompts the user to enter the dorks file name and reads the input.
  4. Opens the specified dorks file and reads each line into a slice of strings.
  5. Prompts the user to enter the number of pages to search and validates the input.
     - Limits the number of pages to a maximum of 15.
  6. Sets up a wait group and context for managing concurrent Bing searches.
  7. Iterates over each dork and performs concurrent searches for the specified number of pages.
  8. Waits for all search goroutines to complete.
  9. Removes duplicate entries from the "found.txt" file using the `removeDuplicates` function.
 10. Counts the total number of unique lines in the "found.txt" file using the `fileLen` function.
 11. Prints the total number of unique lines.
 12. Prints a message indicating the completion of the search.

Error Handling:
  - Prints error messages for various stages (opening dorks file, invalid input, removing duplicates).
  - Exits early if an error occurs while opening the dorks file or reading user input.

Note:
  - The function uses colored console output for different types of messages (input prompts, errors).
  - The maximum number of search pages is limited to 15 for practical reasons.

*/

func main() {
	var dorksFileName string
	clearConsole()
	logo()
	fmt.Printf(" %s░   [INPUT]%s Enter the dorks file name: ", Fore.Green, Style.Reset_all)
	fmt.Scan(&dorksFileName)

	file, err := os.Open(dorksFileName)
	if err != nil {
		fmt.Printf(" %s[ERROR]%s       | opening dorks file: %v\n", Fore.Red, Style.Reset_all, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var dorks []string
	for scanner.Scan() {
		dorks = append(dorks, scanner.Text())
	}

	var pages int
	fmt.Printf(" %s░   [INPUT]%s Number of pages to search (Max 15): ", Fore.Green, Style.Reset_all)
	_, err = fmt.Scan(&pages)
	if err != nil {
		fmt.Printf(" %s[ERROR]%s       | Invalid input: %v\n", Fore.Red, Style.Reset_all, err)
		return
	}
	if pages > 15 {
		pages = 15
	}
	pages *= 10

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, dork := range dorks {
		search := strings.TrimSpace(dork)
		for count := 1; count <= pages; count += 10 {
			wg.Add(1)
			go bing(ctx, search, count, &wg)
		}
	}
	wg.Wait()

	if err := removeDuplicates("found.txt"); err != nil {
		fmt.Printf(" %s[ERROR]%s       | can't Remove Duplicates: %v\n", Fore.Red, Style.Reset_all, err)
	}

	lineCount := strconv.Itoa(fileLen("found.txt"))

	fmt.Printf("total lines: %s\n", lineCount)

	fmt.Println("Search completed.")
}
