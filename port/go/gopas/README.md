# goPAS - CyberArk PAS Go SDK

goPAS is a Go SDK for the CyberArk Privileged Access Security (PAS) REST API. It is a port of the popular [psPAS](https://github.com/pspete/psPAS) PowerShell module, providing the same functionality in a native Go implementation.

## Features

- **Full API Coverage**: Supports all major CyberArk operations including authentication, account management, safe management, user management, and more
- **Multiple Authentication Methods**: CyberArk, LDAP, RADIUS, SAML, and Windows integrated authentication
- **Type-Safe**: Strongly typed request/response structures
- **Context Support**: Full context.Context support for cancellation and timeouts
- **CyberArk v14.0 Compatible**: Supports CyberArk versions up to v14.0

## Installation

```bash
go get github.com/cyberark/gopas
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cyberark/gopas"
)

func main() {
    ctx := context.Background()

    // Create a session
    sess, err := gopas.NewSession(ctx, gopas.SessionOptions{
        BaseURL: "https://cyberark.example.com",
        Credentials: gopas.Credentials{
            Username: "admin",
            Password: "password",
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer gopas.CloseSession(ctx, sess)

    // List accounts
    accounts, err := gopas.ListAccounts(ctx, sess, gopas.ListAccountsOptions{
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, acct := range accounts.Value {
        fmt.Printf("Account: %s@%s\n", acct.UserName, acct.Address)
    }
}
```

## Package Structure

| Package | Description | psPAS Equivalent |
|---------|-------------|------------------|
| `gopas` | Main entry point | N/A |
| `authentication` | Session management | New-PASSession, Close-PASSession |
| `accounts` | Account operations | Get/Add/Set/Remove-PASAccount |
| `safes` | Safe management | Get/Add/Set/Remove-PASSafe |
| `safemembers` | Safe member permissions | Get/Add/Set/Remove-PASSafeMember |
| `users` | User management | Get/New/Set/Remove-PASUser |
| `platforms` | Platform management | Get/Set-PASPlatform |
| `requests` | Access requests | Get/New/Approve/Deny-PASRequest |
| `applications` | Application management | Get/Add/Remove-PASApplication |
| `monitoring` | PSM session monitoring | Get-PASPSMSession |
| `connections` | PSM connections | New-PASPSMSession |
| `eventsecurity` | PTA events | Get/Set-PASPTAEvent |
| `systemhealth` | Component health | Get-PASComponentSummary |
| `ldapdirectories` | LDAP configuration | Get/Add-PASDirectory |
| `onboardingrules` | Onboarding rules | Get/New-PASOnboardingRule |
| `accountgroups` | Account groups | Get/Add-PASAccountGroup |

## Authentication Methods

### CyberArk Native

```go
sess, err := gopas.NewSession(ctx, gopas.SessionOptions{
    BaseURL: "https://cyberark.example.com",
    Credentials: gopas.Credentials{
        Username: "admin",
        Password: "password",
    },
    AuthMethod: gopas.AuthMethodCyberArk,
})
```

### LDAP

```go
sess, err := gopas.NewSession(ctx, gopas.SessionOptions{
    BaseURL: "https://cyberark.example.com",
    Credentials: gopas.Credentials{
        Username: "user@domain.com",
        Password: "password",
    },
    AuthMethod: gopas.AuthMethodLDAP,
})
```

### RADIUS

```go
sess, err := gopas.NewSession(ctx, gopas.SessionOptions{
    BaseURL: "https://cyberark.example.com",
    Credentials: gopas.Credentials{
        Username: "admin",
        Password: "password",
    },
    AuthMethod: gopas.AuthMethodRADIUS,
})
```

## Common Operations

### Working with Accounts

```go
import "github.com/cyberark/gopas/pkg/accounts"

// List accounts
resp, _ := accounts.List(ctx, sess, accounts.ListOptions{
    SafeName: "MySafe",
    Search:   "admin",
})

// Get account by ID
acct, _ := accounts.Get(ctx, sess, "12_34")

// Create account
newAcct, _ := accounts.Create(ctx, sess, accounts.CreateOptions{
    SafeName:   "MySafe",
    PlatformID: "WinServerLocal",
    Address:    "server.example.com",
    UserName:   "admin",
    Secret:     "password123",
})

// Retrieve password
password, _ := accounts.GetPassword(ctx, sess, "12_34", "Authorized access")

// Change password immediately
accounts.ChangeCredentialsImmediately(ctx, sess, "12_34", accounts.ChangeCredentialsOptions{})

// Verify credentials
accounts.VerifyCredentials(ctx, sess, "12_34")

// Reconcile credentials
accounts.ReconcileCredentials(ctx, sess, "12_34")
```

### Working with Safes

```go
import "github.com/cyberark/gopas/pkg/safes"

// List safes
resp, _ := safes.List(ctx, sess, safes.ListOptions{
    Search: "Production",
})

// Get safe
safe, _ := safes.Get(ctx, sess, "MySafe")

// Create safe
newSafe, _ := safes.Create(ctx, sess, safes.CreateOptions{
    SafeName:    "NewSafe",
    Description: "Production accounts",
    ManagingCPM: "PasswordManager",
})

// Update safe
safes.Update(ctx, sess, "MySafe", safes.UpdateOptions{
    Description: "Updated description",
})

// Delete safe
safes.Delete(ctx, sess, "OldSafe")
```

### Working with Safe Members

```go
import "github.com/cyberark/gopas/pkg/safemembers"

// List members
members, _ := safemembers.List(ctx, sess, "MySafe", safemembers.ListOptions{})

// Add member
safemembers.Add(ctx, sess, "MySafe", safemembers.AddOptions{
    MemberName:  "ServiceAccount",
    Permissions: safemembers.DefaultUserPermissions(),
})

// Update member permissions
safemembers.Update(ctx, sess, "MySafe", "ServiceAccount", safemembers.UpdateOptions{
    Permissions: safemembers.DefaultAdminPermissions(),
})

// Remove member
safemembers.Remove(ctx, sess, "MySafe", "OldMember")
```

### Working with Users

```go
import "github.com/cyberark/gopas/pkg/users"

// List users
usersResp, _ := users.List(ctx, sess, users.ListOptions{
    Search: "admin",
})

// Create user
newUser, _ := users.Create(ctx, sess, users.CreateOptions{
    Username:        "newuser",
    InitialPassword: "TempPassword123!",
    UserType:        "EPVUser",
})

// Reset password
users.ResetPassword(ctx, sess, 123, "NewPassword123!")

// Activate suspended user
users.ActivateUser(ctx, sess, 123)
```

### PSM Session Monitoring

```go
import "github.com/cyberark/gopas/pkg/monitoring"

// List all sessions
sessions, _ := monitoring.ListSessions(ctx, sess, monitoring.ListOptions{
    FromTime: time.Now().Add(-24*time.Hour).Unix(),
})

// List live sessions
liveSessions, _ := monitoring.ListLiveSessions(ctx, sess, monitoring.ListOptions{})

// Terminate a live session
monitoring.TerminateSession(ctx, sess, "session-id")

// Get recording
recording, _ := monitoring.GetRecording(ctx, sess, "recording-id")
```

## Error Handling

```go
import "github.com/cyberark/gopas/internal/client"

account, err := accounts.Get(ctx, sess, "invalid-id")
if err != nil {
    if apiErr, ok := client.AsAPIError(err); ok {
        if apiErr.IsNotFound() {
            fmt.Println("Account not found")
        } else if apiErr.IsUnauthorized() {
            fmt.Println("Not authorized")
        } else {
            fmt.Printf("API Error: %s\n", apiErr.ErrorMsg)
        }
    }
}
```

## psPAS to goPAS Mapping

| psPAS Function | goPAS Function |
|----------------|----------------|
| `New-PASSession` | `gopas.NewSession()` |
| `Close-PASSession` | `gopas.CloseSession()` |
| `Get-PASAccount` | `accounts.List()` / `accounts.Get()` |
| `Add-PASAccount` | `accounts.Create()` |
| `Set-PASAccount` | `accounts.Update()` |
| `Remove-PASAccount` | `accounts.Delete()` |
| `Get-PASAccountPassword` | `accounts.GetPassword()` |
| `Invoke-PASCPMOperation` | `accounts.ChangeCredentialsImmediately()` / `accounts.VerifyCredentials()` / `accounts.ReconcileCredentials()` |
| `Get-PASSafe` | `safes.List()` / `safes.Get()` |
| `Add-PASSafe` | `safes.Create()` |
| `Set-PASSafe` | `safes.Update()` |
| `Remove-PASSafe` | `safes.Delete()` |
| `Get-PASSafeMember` | `safemembers.List()` |
| `Add-PASSafeMember` | `safemembers.Add()` |
| `Set-PASSafeMember` | `safemembers.Update()` |
| `Remove-PASSafeMember` | `safemembers.Remove()` |

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [psPAS](https://github.com/pspete/psPAS) - The original PowerShell module this SDK is based on
- [CyberArk](https://www.cyberark.com/) - For providing the REST API documentation
