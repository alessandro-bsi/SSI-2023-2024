#!/bin/bash

# Default variables
output_dir="certs"
certs_db="${output_dir}/certs.db"
config_file="/tmp/openssl.cnf"
default_md="sha256"
email_in_dn=""
domain_name=""
entity_type=""
passphrase=""
common_name=""
country=""
locality=""
organization=""
organizational_unit=""
state=""

# Ensure the output directory exists
mkdir -p "${output_dir}"
touch "${certs_db}"

# Parse command-line flags
while getopts ":e:d:t:p:c:n:l:o:u:s:" opt; do
  case ${opt} in
    e )
      email_in_dn=${OPTARG}
      ;;
    d )
      domain_name=${OPTARG}
      ;;
    t )
      entity_type=${OPTARG}
      ;;
    p )
      passphrase=${OPTARG}
      ;;
    c )
      country=${OPTARG}
      ;;
    s )
      state=${OPTARG}
      ;;
    n )
      common_name=${OPTARG}
      ;;
    l )
      locality=${OPTARG}
      ;;
    o )
      organization=${OPTARG}
      ;;
    u )
      organizational_unit=${OPTARG}
      ;;
    \? )
      echo "Invalid option: $OPTARG" 1>&2
      ;;
    : )
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      ;;
  esac
done

# Function to generate OpenSSL configuration
# Uses global variables email_in_dn and default_md for email and digest algorithm
generate_openssl_config() {
    local is_ca="$1"
    local name="$2"
    # Configuration generation logic
    {
        echo "[ req ]"
        echo "# Default section for the request"
        echo "distinguished_name = req_distinguished_name"
        if [[ "${is_ca}" == "true" ]]; then
          echo "req_extensions = v3_ca"
        else
          echo "req_extensions = req_ext"
        fi
        echo "prompt = no"

        echo "[ req_distinguished_name ]"
        echo "countryName = $country"
        echo "stateOrProvinceName = $state"
        echo "localityName = $locality"
        echo "organizationName = $organization"
        echo "commonName = $common_name"
        echo "organizationalUnitName = $organizational_unit"

        if [[ "${is_ca}" == "true" ]]; then
            echo "# Extensions for a CA certificate"
            echo "[ v3_ca ]"
            echo "basicConstraints = critical, CA:TRUE"
            echo "subjectKeyIdentifier = hash"
            echo "authorityKeyIdentifier = keyid: always, issuer: always"
        else
            echo "# Extensions for server/client certificates"
            echo "[ req_ext ]"
            echo "subjectAltName = @alt_names"
            echo "[ alt_names ]"
            echo "DNS.1 = ${name}"
        fi
        
        # Common footer for both CA and non-CA configs
        echo "[ ca ]"
        echo "default_ca = ca_def"
        echo "[ ca_def ]"
        echo "new_certs_dir = ${output_dir}"
        echo "database = ${certs_db}"
        echo "private_key = ${output_dir}/ca_private_key.pem"
        echo "certificate = ${output_dir}/ca_certificate.pem"
        echo "serial = ${output_dir}/serial"
        echo "rand_serial = ${output_dir}/rserial"
        echo "email_in_dn = ${email_in_dn}"
        echo "default_md = ${default_md}"
        echo "policy = policy_match"
        echo "[ policy_match ]"
        echo "countryName = match"
        echo "stateOrProvinceName = match"
        echo "organizationName = match"
        echo "organizationalUnitName = optional"
        echo "commonName = supplied"
        echo "emailAddress = optional"
    } > "${config_file}"
}

# Function to generate a certificate
# Uses global variable output_dir for the output directory
generate_certificate() {
    local name="$1"
    local is_ca="$2"
    local passphrase="$3"
    # Certificate generation logic 
    local s_name="${name// /_}"

    generate_openssl_config "${is_ca}" "${name}"

    if [[ "${is_ca}" == "true" ]]; then
        # Generate CA private key and self-signed certificate
        openssl genrsa -passout pass:"${passphrase}" -aes256 -out "${output_dir}/ca_private_key.pem" 4096
        openssl req -config "${config_file}" -passin pass:"${passphrase}" -key "${output_dir}/ca_private_key.pem" \
         -new -x509 -days 7300 -sha256 -extensions v3_ca -out "${output_dir}/ca_certificate.pem"
        echo -n "$passphrase" > "${output_dir}/ca_passphrase"
    else
        # Generate a private key and CSR for a server/client, then sign it with the CA's key to issue a certificate
        openssl genrsa -passout pass:"${passphrase}" -out "${output_dir}/${s_name}_server_private_key.pem" 2048
        openssl req -config "${config_file}" -passin pass:"${passphrase}" \
        -key "${output_dir}/${s_name}_server_private_key.pem" -new -sha256 -out "/tmp/${s_name}.csr.pem"
        openssl ca -batch -config "${config_file}" -passin pass:"$(cat "${output_dir}/ca_passphrase")" \
        -days 365 -notext -md sha256 -in "/tmp/${s_name}.csr.pem" \
        -out "${output_dir}/${s_name}_server_certificate.pem"
    fi
    generate_openssl_config "${is_ca}" "${name}"

    if [[ "${is_ca}" == "true" ]]; then
        # Generate CA private key and self-signed certificate
        openssl genrsa -passout pass:"${passphrase}" -aes256 -out "${output_dir}/ca_private_key.pem" 4096
        openssl req -config "${config_file}" -passin pass:"${passphrase}" -key "${output_dir}/ca_private_key.pem" \
        -new -x509 -days 7300 -sha256 -extensions v3_ca -out "${output_dir}/ca_certificate.pem"
    else
        # Generate a private key and CSR for a server/client, then sign it with the CA's key to issue a certificate
        openssl genrsa -passout pass:"${passphrase}" -out "${output_dir}/${s_name}_server_private_key.pem" 2048
        openssl req -config "${config_file}" -passin pass:"${passphrase}" \
        -key "${output_dir}/${s_name}_server_private_key.pem" -new -sha256 -out "/tmp/${s_name}.csr.pem"
        openssl ca -batch -config "${config_file}" -passin pass:"$(cat "${output_dir}/ca_passphrase")" \
        -days 365 -notext -md sha256 -in "/tmp/${s_name}.csr.pem" \
        -out "${output_dir}/${s_name}_server_certificate.pem"
    fi
}

# Main script logic
if [[ -z $state || -z $email_in_dn || -z $domain_name || -z $entity_type || -z $passphrase || -z $country || -z $common_name || -z $locality || -z $organization || -z $organizational_unit ]]; then
    echo "Usage: $0 -e <email> -d <domain_name> -t <type> -p <passphrase> -c <country> -n <common_name> -s <state/province> -l <locality> -o <organization> -u <organizational_unit>"
    echo ""
    echo "Where:"
    echo "  -e <email>                 Specifies the email address in the certificate's DN"
    echo "  -d <domain_name>           Sets the domain name for the certificate"
    echo "  -t <type>                  Type of certificate to generate ('ca' for CA certificates, 'server' for server certificates)"
    echo "  -p <passphrase>            Passphrase for securing the private key"
    echo "  -c <country>               Country Name (2 letter code)"
    echo "  -n <common_name>           Common Name (e.g., YOUR name)"
    echo "  -s <state/province>        Province Name (e.g., province)"
    echo "  -l <locality>              Locality Name (e.g., city)"
    echo "  -o <organization>          Organization Name (e.g., company)"
    echo "  -u <organizational_unit>   Organizational Unit Name (e.g., section)"
    echo ""
    echo "Example:"
    echo "  $0 -e 'email@example.com' -d 'example.com' -t 'server' -p 'myPassphrase' -c 'US' -s 'New York' -n 'My Server' -l 'New York' -o 'My Company' -u 'IT Department'"
    exit 1
fi

is_ca="false"
if [ "$entity_type" = "ca" ]; then
  is_ca="true"
fi

# Generating the OpenSSL config and certificate based on the provided flags
generate_openssl_config "$is_ca" "$domain_name"
generate_certificate "$domain_name" "$is_ca" "$passphrase"

echo "Certificate generation complete."