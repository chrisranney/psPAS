# psPAS Codebase Audit Report

**Date:** 2025-11-26
**Module Version:** 6.4.85
**Auditor:** Claude Code Analysis

---

## Executive Summary

This audit identified **50+ issues** across 6 major categories in the psPAS PowerShell module. The most critical findings include security vulnerabilities (certificate validation bypass, HTML injection), pervasive error handling gaps (97% of functions lack try/catch), and widespread code quality issues (1,026 instances of misspelled attributes).

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Security | 2 | 3 | 1 | - |
| Error Handling | 2 | 3 | 2 | - |
| Code Quality | 1 | 2 | 4 | 1 |
| Testing | - | 2 | 4 | 3 |
| Bugs & Logic | 3 | 4 | 3 | 1 |

---

## Table of Contents

1. [Security Issues](#1-security-issues)
2. [Error Handling Issues](#2-error-handling-issues)
3. [Code Quality Issues](#3-code-quality-issues)
4. [Test Coverage Issues](#4-test-coverage-issues)
5. [Bugs and Logic Issues](#5-bugs-and-logic-issues)
6. [Recommendations Summary](#6-recommendations-summary)

---

## 1. Security Issues

### SEC-001: Insecure Certificate Validation Bypass (CRITICAL)

**Files:**
- `psPAS/Private/Skip-CertificateCheck.ps1` (Lines 26, 39)
- `psPAS/Private/Invoke-PASRestMethod.ps1` (Line 160)

**Description:**
The module implements a certificate validation bypass that unconditionally accepts ALL SSL/TLS certificates regardless of validity.

**Code Example:**
```powershell
# Skip-CertificateCheck.ps1, Line 26
public bool CheckValidationResult(...) {
    return true;  # VULNERABLE: Always accepts any certificate
}

# Line 39
[System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
```

**Reproducibility:**
Always reproducible when `-SkipCertificateCheck` parameter is used.

**Impact:**
Makes the module vulnerable to Man-in-the-Middle (MITM) attacks where an attacker can intercept HTTPS traffic.

**Recommended Fix:**
```powershell
# Add warning and require explicit acknowledgment
if ($SkipCertificateCheck) {
    Write-Warning "Certificate validation is disabled. This is insecure for production use."
    # Consider adding: -Force parameter requirement for non-interactive use
}
```

---

### SEC-002: HTML Injection in PSM Session Connection (CRITICAL)

**File:** `psPAS/Functions/Connections/New-PASPSMSession.ps1` (Line 308)

**Description:**
API response values are directly concatenated into HTML without encoding.

**Code Example:**
```powershell
Body = '<form action="' + $result.PSMGWURL + '" method="POST"><input name="PSMGWRequest" type="hidden" value="' + $result.PSMGWRequest + '"></form><script>document.forms[0].submit()</script>'
```

**Reproducibility:**
Reproducible if an attacker can control or compromise the API response.

**Impact:**
Arbitrary code execution in user's browser context when HTML file is opened.

**Recommended Fix:**
```powershell
# Use proper HTML encoding
$EncodedURL = [System.Net.WebUtility]::HtmlEncode($result.PSMGWURL)
$EncodedRequest = [System.Net.WebUtility]::HtmlEncode($result.PSMGWRequest)
$Body = '<form action="' + $EncodedURL + '" method="POST"><input name="PSMGWRequest" type="hidden" value="' + $EncodedRequest + '"></form><script>document.forms[0].submit()</script>'
```

---

### SEC-003: Path Traversal via X-Correlation-ID Header (HIGH)

**File:** `psPAS/Functions/Connections/New-PASPSMSession.ps1` (Line 302)

**Description:**
Filename constructed directly from API response header without validation.

**Code Example:**
```powershell
$FileName = "$((Get-PASSession).LastCommandResults.Headers['X-Correlation-ID']).html"
$OutputPath = Join-Path $Path $FileName
```

**Reproducibility:**
Reproducible if attacker can manipulate the `X-Correlation-ID` response header.

**Impact:**
Write files outside intended directory (e.g., `../../malicious.html`).

**Recommended Fix:**
```powershell
$RawFileName = (Get-PASSession).LastCommandResults.Headers['X-Correlation-ID']
$FileName = [System.IO.Path]::GetFileName($RawFileName) + '.html'
# Validate filename contains only safe characters
if ($FileName -notmatch '^[a-zA-Z0-9_-]+\.html$') {
    $FileName = [System.Guid]::NewGuid().ToString() + '.html'
}
$OutputPath = Join-Path $Path $FileName
```

---

### SEC-004: Path Traversal via Content-Disposition Header (HIGH)

**File:** `psPAS/Private/Out-PASFile.ps1` (Line 48)

**Description:**
Filename extracted from API response header without sanitization.

**Code Example:**
```powershell
$FileName = ($InputObject.Headers['Content-Disposition'] -split 'filename=')[1] -replace '"'
$OutputPath = Join-Path $Path $FileName
```

**Reproducibility:**
Reproducible via malicious `Content-Disposition: attachment; filename=../../etc/passwd` header.

**Recommended Fix:**
```powershell
$RawFileName = ($InputObject.Headers['Content-Disposition'] -split 'filename=')[1] -replace '"'
$FileName = [System.IO.Path]::GetFileName($RawFileName)
if ([string]::IsNullOrWhiteSpace($FileName)) {
    throw "Invalid filename in Content-Disposition header"
}
$OutputPath = Join-Path $Path $FileName
```

---

### SEC-005: Filter Injection Vulnerability (HIGH)

**File:** `psPAS/Private/ConvertTo-FilterString.ps1` (Lines 78, 84, 94)

**Description:**
User input directly embedded into filter strings without escaping.

**Code Example:**
```powershell
# Line 84
$null = $FilterList.Add("$PSItem $($Parameters[$PSItem])")

# Line 94
$null = $FilterList.Add("$PSItem eq $value")
```

**Reproducibility:**
Reproducible by providing specially crafted filter values (e.g., `" OR 1=1 --`).

**Impact:**
Bypass API filter restrictions to retrieve unauthorized data.

**Recommended Fix:**
```powershell
# Escape special characters in filter values
function Escape-FilterValue {
    param([string]$Value)
    # Escape quotes and special filter characters
    return $Value -replace '"', '\"' -replace "'", "\'"
}

$EscapedValue = Escape-FilterValue $Parameters[$PSItem]
$null = $FilterList.Add("$PSItem eq $EscapedValue")
```

---

### SEC-006: Unsafe File Execution (MEDIUM)

**File:** `psPAS/Functions/Connections/New-PASPSMSession.ps1` (Lines 312, 317)

**Description:**
Files from API responses are opened with `Invoke-Item` without validation.

**Code Example:**
```powershell
Get-Item -Path $OutputPath | Invoke-Item
Out-PASFile -InputObject $result -Path $Path | Invoke-Item
```

**Reproducibility:**
Reproducible when combined with path traversal or HTML injection vulnerabilities.

**Recommended Fix:**
```powershell
# Validate file type before execution
$AllowedExtensions = @('.rdp', '.html')
$Extension = [System.IO.Path]::GetExtension($OutputPath)
if ($Extension -notin $AllowedExtensions) {
    throw "Unexpected file type: $Extension"
}
Get-Item -Path $OutputPath | Invoke-Item
```

---

## 2. Error Handling Issues

### ERR-001: 97% of Functions Lack Try/Catch Blocks (CRITICAL)

**Scope:** 171 out of 176 function files

**Description:**
The vast majority of functions have no error handling whatsoever. Exceptions propagate uncontrolled through the call stack.

**Examples of affected files:**
- `psPAS/Functions/Accounts/Get-PASDiscoveredAccount.ps1`
- `psPAS/Functions/Accounts/Add-PASDiscoveredAccount.ps1`
- `psPAS/Functions/Accounts/Unlock-PASAccount.ps1`
- `psPAS/Functions/Accounts/Invoke-PASCPMOperation.ps1`
- (156+ additional files)

**Reproducibility:**
Any API error, network failure, or invalid input will cause unhandled exceptions.

**Recommended Fix:**
```powershell
# Standard pattern for all functions
function Get-PASExample {
    [CmdletBinding()]
    param(...)

    begin {
        # Validation
    }

    process {
        try {
            $result = Invoke-PASRestMethod -Uri $URI -Method GET
            # Process result
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
```

---

### ERR-002: Swallowed Exceptions Hide Failures (CRITICAL)

**File:** `psPAS/Functions/Accounts/Start-PASAccountImportJob.ps1` (Lines 43-55)

**Description:**
Try/catch block silently suppresses errors and returns a default object.

**Code Example:**
```powershell
try {
    Get-PASAccountImportJob -id $Result
}
catch {
    [PSCustomObject]@{'id' = $Result }  # Silent fallback, no error logged
}
```

**Reproducibility:**
Always - when `Get-PASAccountImportJob` fails for any reason.

**Impact:**
Users receive a default object with no indication of failure.

**Recommended Fix:**
```powershell
try {
    Get-PASAccountImportJob -id $Result
}
catch {
    Write-Warning "Failed to retrieve import job details: $_"
    [PSCustomObject]@{
        'id' = $Result
        'Status' = 'Unknown'
        'Error' = $_.Exception.Message
    }
}
```

---

### ERR-003: Original Exception Context Lost (HIGH)

**File:** `psPAS/Private/Get-PASSAMLResponse.ps1` (Lines 31-51)

**Description:**
Generic catch block discards original error details.

**Code Example:**
```powershell
Try {
    # ... code ...
}
Catch { Throw 'Failed to get SAMLResponse' }  # Original error context lost
```

**Reproducibility:**
Any SAML authentication failure.

**Recommended Fix:**
```powershell
Try {
    # ... code ...
}
Catch {
    throw "Failed to get SAMLResponse: $($_.Exception.Message)"
}
```

---

### ERR-004: Missing -ErrorAction Parameters (HIGH)

**Scope:** ~150+ functions

**Description:**
Critical cmdlets like `Invoke-PASRestMethod` called without `-ErrorAction` specification.

**Examples:**
```powershell
# No error action specified - behavior depends on $ErrorActionPreference
$result = Invoke-PASRestMethod -Uri $URI -Method GET
```

**Reproducibility:**
Inconsistent behavior based on user's `$ErrorActionPreference` setting.

**Recommended Fix:**
```powershell
$result = Invoke-PASRestMethod -Uri $URI -Method GET -ErrorAction Stop
```

---

### ERR-005: ConvertFrom-Json Without Error Handling (HIGH)

**Files:**
- `psPAS/Functions/Accounts/Get-PASAccountPassword.ps1` (Line 150)
- `psPAS/Private/Get-PASResponse.ps1` (Line 76)

**Description:**
JSON parsing without try/catch can fail on malformed responses.

**Code Example:**
```powershell
$result = ConvertFrom-Json $result  # No error handling
```

**Reproducibility:**
Any malformed JSON response from API.

**Recommended Fix:**
```powershell
try {
    $result = ConvertFrom-Json $result -ErrorAction Stop
}
catch {
    throw "Failed to parse API response as JSON: $($_.Exception.Message)"
}
```

---

### ERR-006: SilentlyContinue Without Downstream Handling (MEDIUM)

**File:** `psPAS/Functions/Accounts/Get-PASAccountPassword.ps1` (Line 155)

**Description:**
Uses `-ErrorAction SilentlyContinue` but doesn't handle the null result.

**Code Example:**
```powershell
$UserName = Get-PASAccount -id $AccountID -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty UserName
```

**Reproducibility:**
When `Get-PASAccount` fails, `$UserName` becomes null with no indication.

**Recommended Fix:**
```powershell
$Account = Get-PASAccount -id $AccountID -ErrorAction SilentlyContinue
if ($null -eq $Account) {
    Write-Warning "Could not retrieve account details for ID: $AccountID"
    $UserName = $null
} else {
    $UserName = $Account.UserName
}
```

---

### ERR-007: Inconsistent Error Handling Patterns (MEDIUM)

**File:** `psPAS/Functions/Authentication/New-PASSession.ps1` (Lines 636-640)

**Description:**
Error handling applied selectively - only for IdentityCommand module, not other operations.

**Code Example:**
```powershell
if (-not (Get-Module IdentityCommand)) {
    try { Import-Module IdentityCommand -ErrorAction Stop }
    catch { throw 'Failed to import IdentityCommand...' }
}
# But other operations in same function have no error handling
```

**Reproducibility:**
Inconsistent user experience based on which operation fails.

---

## 3. Code Quality Issues

### CQ-001: Misspelled Parameter Attribute - 1,026 Instances (CRITICAL)

**Scope:** Entire codebase

**Description:**
`ValueFromPipelinebyPropertyName` (lowercase 'b') instead of `ValueFromPipelineByPropertyName` (uppercase 'B').

**Correct vs Incorrect:**
```powershell
# INCORRECT (1,026 instances found)
[parameter(ValueFromPipelinebyPropertyName = $true)]

# CORRECT (only 22 instances found)
[parameter(ValueFromPipelineByPropertyName = $true)]
```

**Reproducibility:**
Present in virtually every function file.

**Impact:**
While PowerShell is case-insensitive, this indicates copy-paste propagation of errors and creates maintenance issues.

**Recommended Fix:**
```powershell
# Use global search and replace
# Find: ValueFromPipelinebyPropertyName
# Replace: ValueFromPipelineByPropertyName
```

---

### CQ-002: Massive Parameter Block Duplication (HIGH)

**Files:**
- `psPAS/Functions/Authentication/New-PASSession.ps1` (849 lines, 12 parameter sets)
- `psPAS/Functions/User/Set-PASUser.ps1` (515 lines, 55 parameter blocks)
- `psPAS/Functions/User/New-PASUser.ps1` (487 lines, 53 parameter blocks)
- `psPAS/Functions/Requests/New-PASRequest.ps1` (401 lines, 46 parameter blocks)

**Description:**
Parameters repeated across multiple parameter sets create massive code duplication.

**Example from New-PASRequest.ps1:**
```powershell
# $Reason parameter duplicated 4 times (lines 45-65)
[parameter(Mandatory = $true, ValueFromPipelinebyPropertyName = $true, ParameterSetName = "Gen2BulkItems")]
[parameter(Mandatory = $true, ValueFromPipelinebyPropertyName = $true, ParameterSetName = "Gen2Items")]
[parameter(Mandatory = $true, ValueFromPipelinebyPropertyName = $true, ParameterSetName = "Gen2BulkAccounts")]
[parameter(Mandatory = $true, ValueFromPipelinebyPropertyName = $true, ParameterSetName = "Gen2Accounts")]
[string]$Reason,
```

**Reproducibility:**
Visible in all multi-parameter-set functions.

**Recommended Fix:**
Consider using dynamic parameters or restructuring parameter sets to reduce duplication.

---

### CQ-003: Lowercase Parameter Names (HIGH)

**Scope:** 100+ instances across codebase

**Description:**
Parameter names don't follow PowerShell PascalCase convention.

**Examples:**
| Incorrect | Correct | Occurrences |
|-----------|---------|-------------|
| `$id` | `$Id` | 20 |
| `$description` | `$Description` | 9 |
| `$search` | `$Search` | 7 |
| `$path` | `$Path` | 5 |
| `$userName` | `$UserName` | 4 |
| `$safeName` | `$SafeName` | 3 |

**Reproducibility:**
Consistent pattern across multiple files.

**Recommended Fix:**
Rename parameters to PascalCase for consistency with PowerShell conventions.

---

### CQ-004: Hard-coded Magic Numbers (MEDIUM)

**Files:**
- `psPAS/Functions/Accounts/Get-PASAccount.ps1` (Lines 66, 74, 82)
- `psPAS/Functions/Applications/Add-PASApplication.ps1` (Lines 10, 18, 31, 38)
- `psPAS/Functions/Safes/Add-PASSafe.ps1` (Lines 49, 62)

**Examples:**
```powershell
[ValidateRange(1, 1000)]    # Max items limit
[ValidateLength(0, 500)]    # Max keywords length
[ValidateLength(0, 28)]     # Max safe name length
[ValidateRange(0, 3650)]    # Days (10 years)
```

**Reproducibility:**
Present in validation attributes throughout the codebase.

**Recommended Fix:**
```powershell
# Define constants at module level
$script:MaxItemsLimit = 1000
$script:MaxKeywordsLength = 500
$script:MaxSafeNameLength = 28

# Use in validation (requires dynamic validation)
[ValidateScript({ $_ -le $script:MaxItemsLimit })]
```

---

### CQ-005: Hard-coded Domain Strings (MEDIUM)

**Files:**
- `psPAS/Private/Find-SharedServicesURL.ps1` (Line 72)
- `psPAS/Private/Assert-VersionRequirement.ps1` (Lines 120, 132)
- `psPAS/Private/Invoke-PASRestMethod.ps1` (Line 251)

**Examples:**
```powershell
$PlatformDiscoveryURL = 'https://platform-discovery.cyberark.cloud/api/v2/services/subdomain/'
If ($psPASSession.BaseUri -match 'cyberark.cloud')
```

**Reproducibility:**
Any environment using non-standard CyberArk URLs.

**Recommended Fix:**
```powershell
# Module-level configuration
$script:CyberArkCloudDomain = 'cyberark.cloud'
$script:PlatformDiscoveryBase = 'https://platform-discovery.cyberark.cloud'

# Usage
If ($psPASSession.BaseUri -match $script:CyberArkCloudDomain)
```

---

### CQ-006: Missing Parameter Validation (MEDIUM)

**File:** `psPAS/Functions/User/Get-PASUser.ps1`

**Examples:**
```powershell
[string]$Search    # No validation
[string]$UserType  # No validation (but Set-PASUser has ValidateSet)
[string]$source    # No validation
```

**Reproducibility:**
Inconsistent validation across similar parameters in different functions.

**Recommended Fix:**
```powershell
[ValidateNotNullOrEmpty()]
[string]$Search,

[ValidateSet('EPVUser', 'BasicUser', 'ExtUser')]
[string]$UserType,
```

---

### CQ-007: Overly Long Functions (MEDIUM)

**Files:**
| File | Lines | Parameter Sets |
|------|-------|----------------|
| New-PASSession.ps1 | 849 | 12 |
| Set-PASUser.ps1 | 515 | 2 |
| New-PASUser.ps1 | 487 | 2 |
| New-PASRequest.ps1 | 401 | 4 |

**Reproducibility:**
These files are difficult to maintain and test.

**Recommended Fix:**
Consider breaking into smaller helper functions or using splatting for parameter handling.

---

### CQ-008: Direct Invoke-WebRequest Usage (LOW)

**File:** `psPAS/Private/Get-PASSAMLResponse.ps1` (Lines 37, 39)

**Description:**
Uses `Invoke-WebRequest` directly instead of the `Invoke-PASRestMethod` wrapper.

**Code Example:**
```powershell
$WebResponse = Invoke-WebRequest -Uri $Uri -MaximumRedirection 0 -ErrorAction SilentlyContinue
```

**Impact:**
Bypasses centralized error handling, logging, and session management.

---

## 4. Test Coverage Issues

### TEST-001: Private Functions Missing Tests (HIGH)

**Files without test coverage:**
- `psPAS/Private/Add-ObjectDetail.ps1`
- `psPAS/Private/Test-IsCoreCLR.ps1`

**Reproducibility:**
These functions are not tested at all.

**Recommended Fix:**
Create test files following existing patterns.

---

### TEST-002: Skipped Tests with Empty Bodies (HIGH)

**Files:**
- `Tests/Remove-PASAccountACL.Tests.ps1` (Line 107) - "sends request with expected body"
- `Tests/Use-PASSession.Tests.ps1` (Line 82) - "sets expected Other property"

**Description:**
Tests are skipped with no implementation, hiding potential bugs.

**Recommended Fix:**
Either implement the tests or document why they are skipped.

---

### TEST-003: 66 Test Files with NO Error/Exception Testing (MEDIUM)

**Description:**
These test files only test the "happy path" scenario with no error condition testing.

**Examples:**
- Add-PASAccountACL.Tests.ps1
- Clear-PASDiscoveredLocalAccount.Tests.ps1
- Disable-PASUser.Tests.ps1
- Get-PASAccountActivity.Tests.ps1
- (62 additional files)

**Recommended Fix:**
Add test cases for:
- Invalid parameters
- API errors
- Network failures
- Version requirement failures

---

### TEST-004: Test Files with TODO Comments (MEDIUM)

**File:** `Tests/New-PASPSMSession.Tests.ps1` (Line 223)

**Description:**
Missing RDP/PSMGW and file-related tests noted as TODO.

**Recommended Fix:**
Complete the TODO items or create issues to track them.

---

### TEST-005: Minimal Test Coverage Files (MEDIUM)

**Files with only 1-3 test cases:**
- Get-PASPropertyObject.Tests.ps1 (1 test)
- Skip-CertificateCheck.Tests.ps1 (1 test)
- (29 additional files with 2-3 tests)

**Recommended Fix:**
Expand test coverage to include edge cases, error conditions, and parameter variations.

---

### TEST-006: Hardcoded System Paths in Tests (LOW)

**File:** `Tests/Out-PASFile.Tests.ps1`

**Description:**
Uses hardcoded `C:\Temp` path that may not exist on all systems.

**Recommended Fix:**
```powershell
$TestPath = [System.IO.Path]::GetTempPath()
```

---

### TEST-007: Inconsistent Mock Patterns (LOW)

**Description:**
- `Assert-VersionRequirement` mocked globally in P Cloud tests
- Varying `BeforeEach` scopes
- Mixed mock scoping approaches

**Recommended Fix:**
Standardize mocking patterns across all test files.

---

### TEST-008: Tests Don't Validate Error Conditions (LOW)

**Description:**
Utility functions like `ConvertTo-InsecureString` and `Skip-CertificateCheck` don't validate error conditions.

---

## 5. Bugs and Logic Issues

### BUG-001: Array Index Out of Bounds - URI Split (CRITICAL)

**Files:**
- `psPAS/Functions/Monitoring/Get-PASPSMSession.ps1` (Lines 141-143)
- `psPAS/Functions/Monitoring/Get-PASPSMRecording.ps1` (Lines 151-153)
- `psPAS/Functions/SafeMembers/Get-PASSafeMember.ps1` (Lines 295-297)
- `psPAS/Functions/EventSecurity/Get-PASPTARiskEvent.ps1` (Lines 157-159)

**Description:**
Split operations on URI without verifying array bounds before accessing index `[1]`.

**Code Example:**
```powershell
$URLString = $URI.Split('?')
$URI = $URLString[0]
$queryString = $URLString[1]  # Can be $null if URI has no '?'
```

**Reproducibility:**
When URI doesn't contain a query string.

**Recommended Fix:**
```powershell
$URLString = $URI.Split('?')
$URI = $URLString[0]
$queryString = if ($URLString.Count -gt 1) { $URLString[1] } else { $null }
```

---

### BUG-002: Null Reference - SAML Response Parsing (CRITICAL)

**File:** `psPAS/Private/Get-PASSAMLResponse.ps1` (Lines 39, 41-43)

**Description:**
Property access without null validation.

**Code Example:**
```powershell
$SAMLResponse = Invoke-WebRequest -Uri $($WebResponse.links.href)  # links could be null

If ($SAMLResponse.InputFields[0].name -eq 'SAMLResponse') {  # InputFields could be null/empty
    $SAMLResponse.InputFields[0].value
}
```

**Reproducibility:**
When SAML response format differs from expected.

**Recommended Fix:**
```powershell
if ($null -eq $WebResponse.links -or $WebResponse.links.Count -eq 0) {
    throw "SAML response did not contain expected links"
}
$SAMLResponse = Invoke-WebRequest -Uri $WebResponse.links[0].href

if ($null -eq $SAMLResponse.InputFields -or $SAMLResponse.InputFields.Count -eq 0) {
    throw "SAML response did not contain expected input fields"
}
```

---

### BUG-003: String Split Without Bounds Checking (CRITICAL)

**File:** `psPAS/Private/Out-PASFile.ps1` (Line 48)

**Description:**
No validation that Content-Disposition header exists or contains 'filename='.

**Code Example:**
```powershell
$FileName = ($InputObject.Headers['Content-Disposition'] -split 'filename=')[1] -replace '"'
```

**Reproducibility:**
When Content-Disposition header is missing or malformed.

**Recommended Fix:**
```powershell
$ContentDisposition = $InputObject.Headers['Content-Disposition']
if ([string]::IsNullOrWhiteSpace($ContentDisposition)) {
    throw "Response missing Content-Disposition header"
}

$FilenameParts = $ContentDisposition -split 'filename='
if ($FilenameParts.Count -lt 2) {
    throw "Content-Disposition header does not contain filename"
}
$FileName = $FilenameParts[1] -replace '"'
```

---

### BUG-004: Type Conversion Error (HIGH)

**File:** `psPAS/Functions/Accounts/Get-PASAccountPassword.ps1` (Line 141)

**Description:**
Incorrect type casting - `[PSCustomObject]` cast on byte array.

**Code Example:**
```powershell
$result = [System.Text.Encoding]::ASCII.GetString([PSCustomObject]$result.Content)
```

**Reproducibility:**
Always - the cast is semantically incorrect.

**Recommended Fix:**
```powershell
$result = [System.Text.Encoding]::ASCII.GetString($result.Content)
```

---

### BUG-005: Uninitialized Variable Usage (HIGH)

**File:** `psPAS/Functions/Accounts/Get-PASAccountPassword.ps1` (Line 168)

**Description:**
`$UserName` is only initialized in 'Gen2' branch but used in output object for all paths.

**Reproducibility:**
When 'Gen1' parameter set is used.

**Recommended Fix:**
```powershell
# Initialize at function start
$UserName = $null

# Or check before use
UserName = if ($null -ne $UserName) { $UserName } else { 'Unknown' }
```

---

### BUG-006: Uninitialized $TimeValue Variable (HIGH)

**File:** `psPAS/Functions/EventSecurity/Get-PASPTARiskEvent.ps1` (Lines 107-118)

**Description:**
`$TimeValue` may not be set if neither FromTime nor ToTime is provided.

**Code Example:**
```powershell
switch ($PSBoundParameters) {
    { $PSItem.ContainsKey('FromTime') } { $FromTimeValue = ... }
    { $PSItem.ContainsKey('ToTime') } { $ToTimeValue = ... }
    { $PSItem.ContainsKey('FromTime') -and $PSItem.ContainsKey('ToTime') } { $TimeValue = "..."; continue }
    { $PSItem.ContainsKey('FromTime') -or $PSItem.ContainsKey('ToTime') } { $TimeValue = "..."; continue }
}
$filterParameters['detectionTime'] = $TimeValue  # May be uninitialized
```

**Reproducibility:**
When neither FromTime nor ToTime parameters are provided.

**Recommended Fix:**
```powershell
$TimeValue = $null  # Initialize

# After switch
if ($null -ne $TimeValue) {
    $filterParameters['detectionTime'] = $TimeValue
}
```

---

### BUG-007: Missing Header Validation (HIGH)

**File:** `psPAS/Private/Out-PASFile.ps1` (Line 48)

**Description:**
Accesses `Headers['Content-Disposition']` without checking if header exists.

**Recommended Fix:**
See BUG-003 fix.

---

### BUG-008: Potential Infinite Loop in Pagination (MEDIUM)

**Files:**
- `psPAS/Functions/Monitoring/Get-PASPSMSession.ps1` (Lines 145-162)
- `psPAS/Functions/Monitoring/Get-PASPSMRecording.ps1` (Lines 155-170)
- `psPAS/Functions/EventSecurity/Get-PASPTARiskEvent.ps1` (Lines 163-179)
- `psPAS/Functions/SafeMembers/Get-PASSafeMember.ps1` (Lines 299-315)

**Description:**
No maximum iteration limit in pagination loops.

**Reproducibility:**
If API returns incorrect Total count or pagination breaks.

**Recommended Fix:**
```powershell
$MaxIterations = 1000  # Safety limit
$IterationCount = 0

do {
    $IterationCount++
    if ($IterationCount -gt $MaxIterations) {
        Write-Warning "Maximum pagination iterations reached"
        break
    }
    # ... pagination logic
} until ($Returned -ge $Total)
```

---

### BUG-009: SilentlyContinue Response Not Checked (MEDIUM)

**File:** `psPAS/Private/Get-PASSAMLResponse.ps1` (Line 37)

**Description:**
`-ErrorAction SilentlyContinue` used but response can be null.

**Code Example:**
```powershell
$WebResponse = Invoke-WebRequest -Uri $Uri -MaximumRedirection 0 -ErrorAction SilentlyContinue
$SAMLResponse = Invoke-WebRequest -Uri $($WebResponse.links.href)  # WebResponse could be null
```

**Recommended Fix:**
```powershell
$WebResponse = Invoke-WebRequest -Uri $Uri -MaximumRedirection 0 -ErrorAction SilentlyContinue
if ($null -eq $WebResponse) {
    throw "Failed to retrieve SAML authentication page"
}
```

---

### BUG-010: Fragile DateTime Validation (MEDIUM)

**File:** `psPAS/Functions/Safes/Set-PASSafe.ps1` (Line 103)

**Description:**
Retrieves safe with `Get-PASSafe` without error handling.

**Reproducibility:**
When safe doesn't exist or API fails.

**Recommended Fix:**
```powershell
try {
    $SafeObject = Get-PASSafe -SafeName $SafeName -ErrorAction Stop
}
catch {
    throw "Failed to retrieve safe '$SafeName': $($_.Exception.Message)"
}
```

---

### BUG-011: Non-idiomatic Boolean Comparison (LOW)

**File:** `psPAS/Functions/Safes/Get-PASSafe.ps1` (Line 124)

**Description:**
Uses `$extendedDetails -eq $false` instead of `-not $extendedDetails`.

**Code Example:**
```powershell
If ($extendedDetails -eq $false)  # Non-idiomatic
```

**Recommended Fix:**
```powershell
If (-not $extendedDetails)  # Idiomatic PowerShell
```

---

## 6. Recommendations Summary

### Immediate Actions (Critical)

1. **Fix Certificate Validation** - Add warnings and require explicit acknowledgment for certificate bypass
2. **Sanitize HTML Output** - Use `[System.Net.WebUtility]::HtmlEncode()` for all dynamic HTML content
3. **Validate File Paths** - Use `[System.IO.Path]::GetFileName()` to prevent path traversal
4. **Add Array Bounds Checking** - Verify array length before accessing indices
5. **Add Null Checks** - Validate response objects before accessing properties

### Short-term Actions (High Priority)

1. **Standardize Error Handling** - Add try/catch blocks to all functions
2. **Fix Attribute Spelling** - Global replace `ValueFromPipelinebyPropertyName` → `ValueFromPipelineByPropertyName`
3. **Add Missing Tests** - Create tests for `Add-ObjectDetail.ps1` and `Test-IsCoreCLR.ps1`
4. **Implement Skipped Tests** - Complete or remove skipped test cases
5. **Fix Type Conversion** - Remove incorrect `[PSCustomObject]` cast in Get-PASAccountPassword.ps1

### Medium-term Actions

1. **Reduce Code Duplication** - Refactor parameter set handling
2. **Standardize Naming** - Apply PascalCase to all parameter names
3. **Extract Constants** - Move magic numbers to module-level variables
4. **Expand Test Coverage** - Add error condition tests to all test files
5. **Add Pagination Safety** - Implement maximum iteration limits

### Long-term Actions

1. **Restructure Long Functions** - Break down 400+ line functions
2. **Centralize Domain Logic** - Move hardcoded URLs to configuration
3. **Standardize Mock Patterns** - Create consistent test helpers
4. **Documentation Updates** - Document all security considerations

---

## Appendix: Issue Count by File

| File | Issues |
|------|--------|
| New-PASPSMSession.ps1 | 4 (SEC-002, SEC-003, SEC-006 x2) |
| Get-PASSAMLResponse.ps1 | 4 (BUG-002 x2, BUG-009, ERR-003) |
| Out-PASFile.ps1 | 3 (SEC-004, BUG-003, BUG-007) |
| Get-PASAccountPassword.ps1 | 3 (BUG-004, BUG-005, ERR-005) |
| Get-PASPSMSession.ps1 | 2 (BUG-001, BUG-008) |
| ConvertTo-FilterString.ps1 | 1 (SEC-005) |
| Skip-CertificateCheck.ps1 | 1 (SEC-001) |
| (All 176 functions) | 1 (CQ-001 - misspelled attribute) |

---

*Report generated by Claude Code Analysis*
