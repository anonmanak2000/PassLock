# Passlock - Password Manager

Passlock is a Command Line Interface (CLI) based password manager designed to centralize password management for multiple users. It provides a secure and convenient way to manage and organize passwords for various tags.

## Features

- **Add Password**: Users can add passwords either by generating a new password or by providing a password for a specific tag.

  ```bash
  passlock -add-password -tag=<tag> (-password=<password>|-generate)
  ```

- **Update Password**: Users can udpate passwords either by generating a new password or by providing a password for a specific tag.

  ```bash
  passlock -update-password -tag=<tag> (-password=<password>|-generate)
  ```

- **Delete Password**: Users can delete passwords by providing specific tag.

  ```bash
  passlock -delete-password -tag=<tag>
  ```

- **Get Password**: Users can get passwords by providing specific tag.

  ```bash
  passlock -get-password -tag=<tag>
  ```

- **Get Tags**: Users can all tags.

  ```bash
  passlock -get-tags
  ```

## Getting Started

### Install Passlock

Clone the repository and install the Passlock CLI on your machine.

```bash
git clone https://github.com/anonmanak2000/PassLock.git
cd passlock
```

#### Create an Account

The first time you run Passlock, you will be prompted to create an account by entering a username and setting up a master password.

#### Execute Commands

After creating an account, use the commands mentioned above to manage your passwords.

#### Usage

Before executing each command, users will be required to enter their username and master password to ensure secure access.

#### Examples

Adding a Password

```bash
passlock -add-password -tag=example -password=mysecretpassword
```

Generating a Password

```bash
passlock -add-password -tag=example -generate
```
