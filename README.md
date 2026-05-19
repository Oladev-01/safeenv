# SafeEnv: Secure Secret Key Sharing for Teams

**SafeEnv** is a high-performance CLI tool designed to encrypt and share secret keys (like `.env` files) among development teams securely. Built with **Go** and powered by **Supabase**, it ensures that sensitive credentials never reside in plain text on unverified machines.

For an extensive, deep-dive breakdown of every single command, configuration flag, and architectural workflow, check out our full [Detailed Documentation Site](https://your-documentation-site-placeholder.com).

---

## 🛠️ Prerequisites

Before installing **SafeEnv**, you must have **Go** (Golang) installed on your machine.

### 1. Install Go
If you do not have Go installed, follow the steps for your operating system:

*   **Windows / macOS**: Download the installer from the [Official Go Downloads page](https://safeenv-doc.vercel.app/) and follow the prompts.
*   **Linux (Ubuntu/Debian)**:
    ```bash
    sudo apt update
    sudo apt install golang-go
    

* **Verify Installation**:
Run the following command in your terminal:
```bash
go version
```

> *Ensure you are running version **1.21** or higher.*

---

## 🚀 Getting Started

### 2. Install SafeEnv
Once Go is ready, install version **v0.1.9** directly from the repository:

```bash
go install github.com/Oladev-01/safeenv/cmd/safeenv@v0.1.9
```

> **Pro-Tip**: Ensure your `$GOPATH/bin` is in your system's PATH to run `safeenv` from any directory.

---

### 3. Backend Setup (Supabase)

SafeEnv uses Supabase as its secure backend. You will need a Supabase project to host your encrypted data.

1. Create a new project at [Supabase](https://supabase.com/).
2. Navigate to the **SQL Editor** in your Supabase dashboard.
3. Copy and run the contents of the `schema.sql` file found in the root of this repository to set up the necessary tables.

---

### 4. Initialization

Connect your local CLI to your backend:

```bash
safeenv init

```

You will be prompted to enter your **Supabase Project URL** and **Service Role Key**.

---

## 📖 Usage & Commands

SafeEnv is built to be self-documenting. If you ever get stuck, help is just a flag away.

### Global Help

To see all available commands and global options, run:

```bash
safeenv --help

```

### Command-Specific Help

Every command supports the `--help` flag. If you want to know more about a specific action, like how to register or create a team, run:

```bash
safeenv register --help
safeenv team create --help
safeenv safe push --help

```

### Common Flow

* **Register**: `safeenv register` — Generates your cryptographic identity.
* **Create Team**: `safeenv team create -t "team_name" -u "username"` — Sets up a new secure project workspace and assigns you as Admin.
* **Invite**: `safeenv team invite -t "team_name"` — Generates a secure, 1-hour valid OTP code for collaborators.
* **Join Team**: `safeenv team join -t "team_name" -u "username" -c "code"` — Allows a collaborator to join an existing team using a valid invite code.
* **Push Secret**: `safeenv safe push .env -t "team_name" --all` — Encrypts and distributes a local secret file to team members.
* **Pull Secret**: `safeenv safe pull .env -t "team_name" -o .env` — Retrieves, verifies, and decrypts a distributed safe file record.

---

## 🛡️ Security Architecture

* **Zero-Knowledge**: Your master private key is encrypted locally before ever leaving your machine.
* **End-to-End Encryption**: Secrets are stored in "envelopes," accessible only to authorized team members.
* **Service-Level Access**: Utilizes the Supabase Service Role for high-speed administrative operations.

---

## 🤝 Contributing

As a project built in public, contributions are welcome!

* **Founder/CTO**: Mojibola Olalekan Qudus
* **Project Path**: `[github.com/Oladev-01/safeenv](https://github.com/Oladev-01/safeenv)`
* **Contact / Support Email**: Reach out directly at **[lekanmojibola@gmail.com](mailto:lekanmojibola@gmail.com)**.

---

**License**: Distributed under the MIT License.

