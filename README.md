# UsengeSda Church Application Docker Setup Guide

This guide will walk you through the process of setting up and running the Flask application using Docker on Windows.

## Prerequisites

Before you begin, make sure you have the following installed on your system:

- Docker Desktop: [Download Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)

## Getting Started

Follow these steps to get the Flask application up and running:

1. **Clone the Repository:**
   - Clone the repository containing the Flask application to your local machine.

2. **Navigate to the Repository Directory:**
   - Open a terminal or command prompt and navigate to the directory where you cloned the repository.

3. **Build the Docker Image:**
   - Run the following command to build the Docker image:

     ```bash
     docker build -t flask-app .
     ```

4. **Run the Docker Container:**
   - Once the Docker image is built, start a Docker container using the following command:

     ```bash
     docker run -p 5000:5000 flask-app
     ```

5. **Access the Flask Application:**
   - Open a web browser and navigate to `http://localhost:5000` to access the Flask application.

## Additional Information

- **Port Configuration:**
  - By default, the Flask application runs on port 5000 inside the Docker container. The `-p 5000:5000` flag in the `docker run` command maps port 5000 on the host machine to port 5000 on the Docker container. If you need to use a different port, modify the port mapping accordingly.

- **Troubleshooting:**
  - If you encounter any issues during setup or while running the Docker container, refer to the Docker documentation or search for solutions online. Feel free to reach out to the repository owner for assistance if needed.

## License

This project is licensed under the [MIT License](LICENSE).
