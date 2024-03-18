function SSInvoke-PreCheck {
    if (-NOT (
    [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Must be run as an administrator in an elevated IL process"
        throw "Please relaunch this process as an elevated process (Run as administrator)"
    }
}

function SSInvoke-Clean {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="The name to filter for the cleanup")]
        [string]$CommonName
    )
    Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.Subject -match $CommonName } | Remove-Item
}

function SSInvoke-GenerateCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="The name for the newly created Certificate")]
        [string]$Name,
        [Parameter(Mandatory=$True, HelpMessage="The Subject for the newly created Certificate")]
        [string]$Subject,
        [Parameter(Mandatory=$True, HelpMessage="DNS name for the newly created Certificate")]
        [string]$DNSName,
        [Parameter(Mandatory=$True, HelpMessage="Password to encrypt the PFX Certificate")]
        [string]$Passphrase,
        [Parameter(Mandatory=$True, HelpMessage="Password to export the PFX Certificate")]
        [string]$OutputDir,
        [Parameter(Mandatory=$True, HelpMessage="Path to the CA certificate (required for server certs)")]
        [string]$CAFilePath, # Required only for server certificates,
        [Parameter(Mandatory=$False, HelpMessage="Password for the CA cert (required for server certs)")]
        [string]$CACertPass # Required only for server certificates
    )

    $SecurePassphrase = ConvertTo-SecureString -String $CACertPass -Force -AsPlainText
    $RootCert = Get-PfxData -FilePath $CAFilePath -Password $SecurePassphrase

    $cert = New-SelfSignedCertificate -DnsName $DNSName -CertStoreLocation "cert:\LocalMachine\My"      `
     -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1) -Subject $Subject -Signer                      `
     "cert:\LocalMachine\My\$($RootCert.EndEntityCertificates.ThumbPrint)" -KeyAlgorithm RSA            `
     -KeyLength 2048

    $CertPath = Join-Path -Path $OutputDir -ChildPath ($Name + ".crt")
    Export-Certificate -Cert $cert -FilePath $CertPath

    $PfxPath = Join-Path -Path $OutputDir -ChildPath ($Name + ".pfx")
    Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $SecurePassphrase
}

function SSInvoke-GenerateCACertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="The name for the newly created Certificate")]
        [string]$Name,
        [Parameter(Mandatory=$True, HelpMessage="The Subject for the newly created Certificate")]
        [string]$Subject,
        [Parameter(Mandatory=$True, HelpMessage="DNS name for the newly created Certificate")]
        [string]$DNSName,
        [Parameter(Mandatory=$True, HelpMessage="Password to encrypt the PFX Certificate")]
        [string]$Passphrase,
        [Parameter(Mandatory=$True, HelpMessage="Path to export the PFX Certificate in")]
        [string]$OutputDir
    )

    $SecurePassphrase = ConvertTo-SecureString -String $Passphrase -Force -AsPlainText

    $RootCert = New-SelfSignedCertificate -DnsName $DNSName -CertStoreLocation "cert:\LocalMachine\My"  `
     -KeyUsageProperty All -KeyUsage CertSign, CRLSign, DigitalSignature -KeyExportPolicy Exportable    `
     -KeyAlgorithm RSA -KeyLength 4096 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(10)          `
     -Subject $Subject

    $PfxPath = Join-Path -Path $OutputDir -ChildPath "MyCA.pfx"
    Export-PfxCertificate -Cert $RootCert -FilePath $PfxPath -Password $SecurePassphrase
}

function SSInvoke-Generator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="The name for the newly created Certificate")]
        [string]$Name,
        [Parameter(Mandatory=$False, HelpMessage="The Subject for the newly created Certificate")]
        [string]$Subject,
        [Parameter(Mandatory=$True, HelpMessage="DNS name for the newly created Certificate")]
        [string]$DNSName,
        [Parameter(Mandatory=$False, HelpMessage="Email Address for Distinguished Name")]
        [string]$EmailAddress,
        [Parameter(Mandatory=$True, HelpMessage="Password to encrypt the PFX Certificate")]
        [string]$Passphrase,
        [Parameter(Mandatory=$True, HelpMessage="Password to export the PFX Certificate")]
        [string]$OutputDir,
        [Parameter(Mandatory=$True, HelpMessage="Type of Certificate")]
        [string]$Type, # "CA" or "Server"
        [Parameter(Mandatory=$False, HelpMessage="Path to the CA certificate (required for server certs)")]
        [string]$CAFilePath, # Required only for server certificates,
        [Parameter(Mandatory=$False, HelpMessage="Password for the CA cert (required for server certs)")]
        [string]$CACertPass # Required only for server certificates
    )

    SSInvoke-PreCheck

    # Ensure output directory exists
    if (-not (Test-Path -Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir
    }

    # If a subject is not provided, use the name as CommonName
    if ([System.String]::IsNullOrWhiteSpace($Subject)){
        $Subject = "CN=$Name"
    }

    switch ($Type) {
        "CA" {
            SSInvoke-GenerateCACertificate -Name $Name -DNSName $DNSName -Passphrase $Passphrase `
            -OutputDir $OutputDir -Subject $Subject
        }
        "Server" {
            if (-not [System.String]::IsNullOrWhiteSpace($CAFilePath) -and (Test-Path -Path $CAFilePath)) {
                if(-not [System.String]::IsNullOrWhiteSpace($CACertPass)){
                    SSInvoke-GenerateCertificate -Name $Name -DNSName $DNSName -Passphrase $Passphrase -CAFilePath `
                    $CAFilePath -OutputDir $OutputDir -CACertPass $CACertPass -Subject $Subject
                }
                else{
                    Write-Error "For server certificates, the CA pk password must be provided."
                    return
                }
            }
            else {
                Write-Error "For server certificates, a valid CA file path must be provided."
                return
            }
        }
        default {
            Write-Error "Unsupported certificate type. Please specify 'CA' or 'Server'."
            return
        }
    }
}

# Example usage:
# Generate a CA certificate
# SSInvoke-Generator -Name "My CA" -DNSName "ca.example.com" -Passphrase "MyCASecurePass123" `
#  -OutputDir "C:\Certs" -Type "CA" -Subject "CN=My CA, OU=IT Dep, O=SSI, L=Rome, C=IT, E=admin@test.com"

# Generate a server certificate (after generating a CA certificate and specifying its path)
# SSInvoke-Generator -Name "My Server" -DNSName "server.example.com" -Passphrase "SecurePass123" `
#  -OutputDir "C:\Certs" -Type "Server" -CAFilePath "C:\Certs\MyCA.pfx" -CACertPass "MyCASecurePass123"
#  -Subject "CN=My Server, OU=IT Dep, O=SSI, L=Rome, C=IT, E=admin@test.com"