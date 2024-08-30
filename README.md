# CORD.go
CORD.go is a Golang library that provides a collection of classes and methods to interact with the Cord blockchain network.

## Building the SDK

To build the SDK and see changes, follow these steps:

1. Clone this repository to your local machine:

   ```bash
   git clone <repository_url>
   cd <repository_directory>

2. Install dependencies:

   Make sure that subkey command line utility is installed and added to $PATH variable, [for detailed installation guide](https://docs.substrate.io/reference/command-line-tools/subkey/)

     ```bash
     go get
     ```

     ```bash
     cd demo
     go get
     ```

## Experimenting with SDK Methods
## Demo Methods
Once the SDK is built, you can experiment with the provided methods.

## Statement Method:

The `demo-statement` method allows you to interact with statement-related functionalities.

To run the statement demo, execute the following command:

```bash
cd demo
go run main.go
```

The output of each demo script will demonstrate the functionality of the corresponding method. For a detailed structure of the demo scripts, refer to the source code.