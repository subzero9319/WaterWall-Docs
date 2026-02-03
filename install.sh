#!/bin/bash

#colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
rest='\033[0m'

# Detect the Linux distribution
detect_distribution() {
	if [ -f /etc/os-release ]; then
		source /etc/os-release
		case "${ID}" in
		ubuntu | debian)
			p_m="apt-get"
			;;
		centos)
			p_m="yum"
			;;
		fedora)
			p_m="dnf"
			;;
		*)
			echo -e "${red}Unsupported distribution!${rest}"
			exit 1
			;;
		esac
	else
		echo -e "${red}Unsupported distribution!${rest}"
		exit 1
	fi
}

# Install Dependencies
check_dependencies() {
	detect_distribution

	local dependencies
	dependencies=("wget" "curl" "unzip" "socat" "jq")

	for dep in "${dependencies[@]}"; do
		if ! command -v "${dep}" &>/dev/null; then
			echo -e "${cyan} ${dep} ${yellow}is not installed. Installing...${rest}"
			sudo "${p_m}" install "${dep}" -y
		fi
	done
}

# Check and nstall waterwall
install_waterwall() {
	LATEST_RELEASE=$(curl --silent "https://api.github.com/repos/radkesvat/WaterWall/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')
	INSTALL_DIR="/root/Waterwall"
	FILE_NAME="Waterwall"

	if [ ! -f "$INSTALL_DIR/$FILE_NAME" ]; then
		check_dependencies
		echo ""
		echo -e "${cyan}============================${rest}"
		echo -e "${cyan}Installing Waterwall...${rest}"

		if [ -z "$LATEST_RELEASE" ]; then
			echo -e "${red}Failed to get the latest release version.${rest}"
			return 1
			LATEST_RELEASE
		fi

		echo -e "${cyan}Latest version: ${yellow}${LATEST_RELEASE}${rest}"

		# Determine the download URL based on the architecture
		ARCH=$(uname -m)
		if [ "$ARCH" == "x86_64" ]; then
			DOWNLOAD_URL="https://github.com/radkesvat/WaterWall/releases/download/${LATEST_RELEASE}/Waterwall-linux-clang-x64.zip"
		elif [ "$ARCH" == "aarch64" ]; then
			DOWNLOAD_URL="https://github.com/radkesvat/WaterWall/releases/download/${LATEST_RELEASE}/Waterwall-linux-arm64.zip"
		else
			echo -e "${red}Unsupported architecture: $ARCH${rest}"
			return 1
		fi

		# Create the installation directory if it doesn't exist
		mkdir -p "$INSTALL_DIR"

		# Download the ZIP file directly into INSTALL_DIR
		ZIP_FILE="$INSTALL_DIR/Waterwall.zip"
		curl -L -o "$ZIP_FILE" "$DOWNLOAD_URL"
		if [ $? -ne 0 ]; then
			echo -e "${red}Download failed.${rest}"
			return 1
		fi

		# Unzip the downloaded file directly into INSTALL_DIR
		unzip "$ZIP_FILE" -d "$INSTALL_DIR" >/dev/null 2>&1
		if [ $? -ne 0 ]; then
			echo -e "${red}Unzip failed.${rest}"
			rm -f "$ZIP_FILE"
			return 1
		fi

		rm -f "$ZIP_FILE"

		# Set executable permission for Waterwall binary
		sudo chmod +x "$INSTALL_DIR/$FILE_NAME"
		if [ $? -ne 0 ]; then
			echo -e "${red}Failed to set executable permission for Waterwall.${rest}"
			return 1
		fi

		echo -e "${green}Waterwall installed successfully in $INSTALL_DIR.${rest}"
		echo -e "${cyan}============================${rest}"
		return 0
	fi
}

#===================================

#10
# SSL CERTIFICATE
install_acme() {
	cd ~
	echo -e "${green}install acme...${rest}"

	curl https://get.acme.sh | sh
	if [ $? -ne 0 ]; then
		echo -e "${red}install acme failed${rest}"
		return 1
	else
		echo -e "${green}install acme succeed${rest}"
	fi

	return 0
}

# SSL Menu
ssl_cert_issue_main() {
	echo -e "${yellow}      ***************************${rest}"
	echo -e "${yellow}      |${purple} [1]${green} Get SSL Certificate${yellow} |${rest}"
	echo -e "${yellow}      |${purple} [2]${green} Revoke${yellow}              |${rest}"
	echo -e "${yellow}      |${purple} [3]${green} Force Renew${yellow}         |${rest}"
	echo -e "${yellow}      |${blue}*************************${yellow}|${rest}"
	echo -e "${yellow}      |${purple}  [0]${green} Back to Main Menu${yellow}  |${rest}"
	echo -e "${yellow}      ***************************${rest}"
	echo -en "${cyan}      Enter your choice (1-3): ${rest}"
	read -r choice
	case "$choice" in
	0)
		main
		;;
	1)
		ssl_cert_issue
		;;
	2)
		local domain=""
		echo -e "${cyan}============================================${rest}"
		echo -en "${green}Please enter your domain name to revoke the certificate: ${rest}"
		read -r domain
		~/.acme.sh/acme.sh --revoke -d "${domain}"
		if [ $? -ne 0 ]; then
			echo -e "${cyan}============================================${rest}"
			echo -e "${red}Failed to revoke certificate. Please check logs.${rest}"
		else
			echo -e "${cyan}============================================${rest}"
			echo -e "${green}Certificate revoked${rest}"
		fi
		;;
	3)
		local domain=""
		echo -e "${cyan}============================================${rest}"
		echo -en "${green}Please enter your domain name to forcefully renew an SSL certificate: ${rest}"
		read -r domain
		~/.acme.sh/acme.sh --renew -d "${domain}" --force
		if [ $? -ne 0 ]; then
			echo -e "${cyan}============================================${rest}"
			echo -e "${red}Failed to renew certificate. Please check logs.${rest}"
		else
			echo -e "${cyan}============================================${rest}"
			echo -e "${green}Certificate renewed${rest}"
		fi
		;;
	*) echo -e "${red}Invalid choice${rest}" ;;
	esac
}

ssl_cert_issue() {
	echo -e "${cyan}============================================${rest}"
	release=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
	# check for acme.sh first
	if [ ! -f ~/.acme.sh/acme.sh ]; then
		echo -e "${green}acme.sh could not be found. we will install it${rest}"
		install_acme
		if [ $? -ne 0 ]; then
			echo -e "${red}install acme failed, please check logs${rest}"
			exit 1
		fi
	fi

	# install socat second
	case "${release}" in
	ubuntu | debian | armbian)
		apt update -y
		;;
	centos | almalinux | rocky | oracle)
		yum -y update
		;;
	fedora)
		dnf -y update
		;;
	arch | manjaro | parch)
		pacman -Sy --noconfirm socat
		;;
	*)
		echo -e "${red}Unsupported operating system. Please check the script and install the necessary packages manually.${rest}\n"
		exit 1
		;;
	esac
	if [ $? -ne 0 ]; then
		echo -e "${red}install socat failed, please check logs${rest}"
		exit 1
	else
		echo -e "${cyan}============================${rest}"
	fi

	# get the domain here,and we need verify it
	local domain=""
	echo -en "${green}Please enter your domain name: ${rest}"
	read -r domain
	echo -e "${green}Your domain is:${yellow}${domain}${green},check it...${rest}"

	# check if there already exists a cert
	local currentCert
	currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')

	if [ "${currentCert}" == "${domain}" ]; then
		local certInfo
		certInfo=$(~/.acme.sh/acme.sh --list)
		echo -e "${red}system already has certs here,can not issue again,Current certs details:${rest}"
		echo -e "${green} $certInfo${rest}"
		exit 1
	else
		echo -e "${green} your domain is ready for issuing cert now...${rest}"
	fi

	# create a directory for install cert
	certPath="/root/Waterwall/cert"
	if [ ! -d "$certPath" ]; then
		mkdir -p "$certPath"
	else
		rm -rf "$certPath"
		mkdir -p "$certPath"
	fi

	# get needed port here
	echo -e "${cyan}============================================${rest}"
	echo -en "${green}Please choose which port you want to use [${yellow}Default: 80${green}]: ${rest}"
	read -r WebPort
	WebPort=${WebPort:-80}
	if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
		echo -e "${red}your input ${WebPort} is invalid,will use default port${rest}"
		WebPort=80
	fi
	echo -e "${green} will use port:${WebPort} to issue certs,please make sure this port is open...${rest}"
	echo -e "${cyan}============================================${rest}"
	# issue the cert
	~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
	~/.acme.sh/acme.sh --issue -d "${domain}" --listen-v6 --standalone --httpport "${WebPort}"
	if [ $? -ne 0 ]; then
		echo -e "${red}issue certs failed,please check logs${rest}"
		rm -rf ~/.acme.sh/"${domain}"
		exit 1
	else
		echo -e "${yellow}issue certs succeed,installing certs...${rest}"
	fi
	# install cert
	~/.acme.sh/acme.sh --installcert -d "${domain}" \
		--key-file /root/Waterwall/cert/privkey.pem \
		--fullchain-file /root/Waterwall/cert/fullchain.pem

	if [ $? -ne 0 ]; then
		echo -e "${red}install certs failed,exit${rest}"
		rm -rf ~/.acme.sh/"${domain}"
		exit 1
	else
		echo -e "${green} install certs succeed,enable auto renew...${rest}"
	fi

	~/.acme.sh/acme.sh --upgrade --auto-upgrade
	if [ $? -ne 0 ]; then
		echo -e "${red}auto renew failed, certs details:${rest}"
		ls -lah "$certPath"/*
		chmod 755 "$certPath"/*
		exit 1
	else
		echo -e "${green} auto renew succeed, certs details:${rest}"
		ls -lah "$certPath"/*
		chmod 755 "$certPath"/*
	fi

	sudo systemctl restart trojan.service >/dev/null 2>&1
	sudo systemctl restart Waterwall.service >/dev/null 2>&1
}
#===================================

#00
# Core.json
create_core_json() {
	if [ ! -d /root/Waterwall ]; then
		mkdir -p /root/Waterwall
	fi

	if [ ! -f ~/Waterwall/core.json ]; then
		echo -e "${cyan}Creating core.json...${rest}"
		echo ""
		cat <<EOF >~/Waterwall/core.json
{
    "log": {
        "path": "log/",
        "core": {
            "loglevel": "DEBUG",
            "file": "core.log",
            "console": true
        },
        "network": {
            "loglevel": "DEBUG",
            "file": "network.log",
            "console": true
        },
        "dns": {
            "loglevel": "SILENT",
            "file": "dns.log",
            "console": false
        }
    },
    "dns": {},
    "misc": {
        "workers": 0,
        "ram-profile": "server",
        "libs-path": "libs/"
    },
    "configs": [
        "config.json"
    ]
}
EOF
	fi
}

#===================================

#0
# Trojan Core.json
create_trojan_core_json() {
	if [ ! -d /root/Waterwall/trojan ]; then
		mkdir -p /root/Waterwall/trojan
	fi

	if [ ! -f ~/Waterwall/trojan/core.json ]; then
		echo -e "${cyan}Creating core.json...${rest}"
		echo ""
		cat <<EOF >~/Waterwall/trojan/core.json
{
    "log": {
        "path": "log/",
        "core": {
            "loglevel": "DEBUG",
            "file": "core.log",
            "console": true
        },
        "network": {
            "loglevel": "DEBUG",
            "file": "network.log",
            "console": true
        },
        "dns": {
            "loglevel": "SILENT",
            "file": "dns.log",
            "console": false
        }
    },
    "dns": {},
    "misc": {
        "workers": 0,
        "ram-profile": "server",
        "libs-path": "libs/"
    },
    "configs": [
        "trojan_config.json"
    ]
}
EOF
	fi
}
#===================================

#1
# Simple Tunnel
simple_direct() {
	# Function to create simple port to port config
	create_simple_port_to_port() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local port: ${rest}"
		read -r local_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote port: ${rest}"
		read -r remote_port
		echo -en "${green}Do you want to Enable PreConnect (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r PreConnect
		if [ "$PreConnect" != "no" ]; then
			echo -en "${green}Enter Minimum-unused [${yellow}Default: 1${green}]: ${rest}"
			read -r min_un
			min_un=${min_un:-1}
		fi

		install_waterwall

		if [ "$PreConnect" == "no" ]; then
			output="output"
			preconnect_block=""
		else
			output="precon_client"
			preconnect_block=$(
				cat <<EOF
{
	    "name": "precon_client",
	    "type": "PreConnectClient",
	    "settings": {
	        "minimum-unused": $min_un
	    },
	    "next": "output"
	},
EOF
			)
		fi

		cat <<EOF >/root/Waterwall/config.json
{
    "name": "simple_port_to_port",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "$output"
        },
        $preconnect_block
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
	}

	# Function to create simple multiport to port config
	create_simple_multiport_to_port() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote port: ${rest}"
		read -r remote_port
		echo -en "${green}Do you want to Enable PreConnect (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r PreConnect
		if [ "$PreConnect" != "no" ]; then
			echo -en "${green}Enter Minimum-unused [${yellow}Default: 1${green}]: ${rest}"
			read -r min_un
			min_un=${min_un:-1}
		fi

		install_waterwall

		if [ "$PreConnect" == "no" ]; then
			output="output"
			preconnect_block=""
		else
			output="precon_client"
			preconnect_block=$(
				cat <<EOF
{
	    "name": "precon_client",
	    "type": "PreConnectClient",
	    "settings": {
	        "minimum-unused": $min_un
	    },
	    "next": "output"
	},
EOF
			)
		fi

		cat <<EOF >/root/Waterwall/config.json
{
    "name": "simple_multiport_to_port",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "$output"
        },
        $preconnect_block
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
	}

	# Function to create multiport to multiport config
	create_simple_multiport() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Do you want to Enable PreConnect (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r PreConnect
		if [ "$PreConnect" != "no" ]; then
			echo -en "${green}Enter Minimum-unused [${yellow}Default: 1${green}]: ${rest}"
			read -r min_un
			min_un=${min_un:-1}
		fi

		install_waterwall

		if [ "$PreConnect" == "no" ]; then
			output="output"
			preconnect_block=""
		else
			output="precon_client"
			preconnect_block=$(
				cat <<EOF
{
	    "name": "precon_client",
	    "type": "PreConnectClient",
	    "settings": {
	        "minimum-unused": $min_un
	    },
	    "next": "output"
	},
EOF
			)
		fi

		cat <<EOF >/root/Waterwall/config.json
{
    "name": "simple_multiport",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "$output"
        },
        $preconnect_block
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": "src_context->port"
            }
        }
    ]
}
EOF
	}

	# Function to create simple port to port x2 config
	create_simple_port_to_port_x2() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local port${cyan}s${green} (${yellow}comma-separated${green}): ${rest}"
		read -r local_ports
		echo -en "${green}Enter the remote ${cyan}address ${green}or ${cyan}addresses(${yellow}comma-separated${green}):${rest} "
		read -r remote_addresses
		echo -en "${green}Enter the remote port${cyan}s ${green}(${yellow}comma-separated${green}): ${rest}"
		read -r remote_ports

		IFS=',' read -ra local_ports_array <<<"$local_ports"
		IFS=',' read -ra remote_addresses_array <<<"$remote_addresses"
		IFS=',' read -ra remote_ports_array <<<"$remote_ports"

		if [ ${#remote_addresses_array[@]} -eq 1 ]; then
			single_remote_address="${remote_addresses_array[0]}"
			remote_addresses_array=()
			for ((i = 0; i < ${#local_ports_array[@]}; i++)); do
				remote_addresses_array+=("$single_remote_address")
			done
		fi

		if [ ${#local_ports_array[@]} -ne ${#remote_addresses_array[@]} ] || [ ${#local_ports_array[@]} -ne ${#remote_ports_array[@]} ]; then
			echo -e "${red}Error: Number of local ports, remote addresses, and remote ports must be equal.${rest}"
			return 1
		fi

		install_waterwall

		cat <<EOF >/root/Waterwall/config.json
{
    "name": "simple_port_to_port_x2",
    "nodes": [
EOF

		for i in "${!local_ports_array[@]}"; do
			local_port="${local_ports_array[$i]}"
			remote_address="${remote_addresses_array[$i]}"
			remote_port="${remote_ports_array[$i]}"

			cat <<EOF >>/root/Waterwall/config.json
        {
            "name": "input$((i + 1))",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "output$((i + 1))"
        },
        {
            "name": "output$((i + 1))",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }$([ "$i" -lt $((${#local_ports_array[@]} - 1)) ] && echo ",")
EOF
		done

		cat <<EOF >>/root/Waterwall/config.json
    ]
}
EOF
	}

	echo -e "${yellow}      *************************************${rest}"
	echo -e "${yellow}      | ${purple}[1]${green} Simple port to port${yellow}           |${rest}"
	echo -e "${yellow}      | ${purple}[2]${green} Simple Multiport to port${yellow}      |${rest}"
	echo -e "${yellow}      | ${purple}[3]${green} Simple Multiport to Multiport${yellow} |${rest}"
	echo -e "${yellow}      | ${purple}[4]${green} Simple port to same port x2${yellow}   |${rest}"
	echo -e "${yellow}      |${blue}***********************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple}[0] ${green}Back to ${purple}Main Menu${yellow}             |${rest}"
	echo -e "${yellow}      *************************************${rest}"
	echo -en "      ${cyan}Enter your choice (1-4): ${rest}"
	read -r choice

	case $choice in
	1)
		create_simple_port_to_port
		waterwall_service
		;;
	2)
		create_simple_multiport_to_port
		waterwall_service
		;;
	3)
		create_simple_multiport
		waterwall_service
		;;
	4)
		create_simple_port_to_port_x2
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================

#2
# Tls Tunnel
tls() {
	# Function to create tls port to port iran
	create_tls_port_to_port_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter Your Domain:${rest} "
		read -r domain
		echo -en "${green}Enter the local (${yellow}Client Config${green}) port: ${rest}"
		read -r local_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote (${yellow}Connection${green}) port: ${rest}"
		read -r remote_port
		echo -en "${green}Do you want to Enable Http2 ? (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r http2
		http2=${http2:-yes}
		if [ "$http2" == "no" ]; then
			echo -en "${green}Do you want to Enable PreConnect ? (yes/no) [${yellow}Default: yes${green}]: ${rest}"
			read -r PreConnect
			PreConnect=${PreConnect:-yes}
			if [ "$PreConnect" != "no" ]; then
				echo -en "${green}Enter Minimum-unused [${yellow}Default: 1${green}]: ${rest}"
				read -r min_un
				min_un=${min_un:-1}
			fi
			echo -e "${cyan}============================${rest}"
		fi

		if [ "$http2" == "no" ] && [ "$PreConnect" == "no" ]; then
			output="sslclient"
		elif [ "$http2" == "no" ] && [ "$PreConnect" == "yes" ]; then
			output="precon_client"
		else
			output="pbclient"
		fi

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "tls_port_to_port_iran",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "$output"
        },
EOF
		)

		if [ "$http2" == "yes" ]; then
			json+=$(
				cat <<EOF

        {
            "name": "pbclient",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "$domain",
                "port": $remote_port,
                "path": "/",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
EOF
			)
		else
			if [ "$PreConnect" == "yes" ]; then
				json+=$(
					cat <<EOF

        {
            "name": "precon_client",
            "type": "PreConnectClient",
            "settings": {
                "minimum-unused": $min_un
            },
            "next": "sslclient"
        },
EOF
				)
			fi
		fi

		if [ "$http2" == "yes" ]; then
			alpn="h2"
		else
			alpn="http/1.1"
		fi

		json+=$(
			cat <<EOF
		
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "$domain",
                "verify": true,
                "alpn": "$alpn"
            },
            "next": "output"
        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	# Function to create tls port to port config
	create_tls_port_to_port_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local (${yellow}Connection${green}) port: ${rest}"
		read -r local_port
		echo -en "${green}Enter the remote (${yellow}Server Config${green}) port: ${rest}"
		read -r remote_port
		echo -en "${green}Do you want to Enable Http2 ? (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r http2
		http2=${http2:-yes}

		if [ "$http2" == "yes" ]; then
			output="h2server"
		else
			output="output"
		fi

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "tls_port_to_port_kharej",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "sslserver"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ]
            },
            "next": "$output"  
        },
EOF
		)

		if [ "$http2" == "yes" ]; then
			json+=$(
				cat <<EOF

        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "pbserver"
        },
        {
            "name": "pbserver",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "output"
        },
EOF
			)
		fi

		json+=$(
			cat <<EOF
		
        {
            "name": "output",
            "type": "Connector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
	}

	# Function to create tls multi port iran
	create_tls_multi_port_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter Your Domain: ${rest}"
		read -r domain
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote (${yellow}Connection${green}) port: ${rest}"
		read -r remote_port
		echo -en "${green}Do you want to Enable Http2 ? (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r http2
		http2=${http2:-yes}
		if [ "$http2" == "no" ]; then
			echo -en "${green}Do you want to Enable PreConnect ? (yes/no) [${yellow}Default: yes${green}]: ${rest}"
			read -r PreConnect
			PreConnect=${PreConnect:-yes}
			if [ "$PreConnect" != "no" ]; then
				echo -en "${green}Enter Minimum-unused [${yellow}Default: 1${green}]: ${rest}"
				read -r min_un
				min_un=${min_un:-1}
			fi
			echo -e "${cyan}============================${rest}"
		fi

		if [ "$http2" == "no" ] && [ "$PreConnect" == "no" ]; then
			output="sslclient"
		elif [ "$http2" == "no" ] && [ "$PreConnect" == "yes" ]; then
			output="precon_client"
		else
			output="pbclient"
		fi

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "tls_multiport_iran",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "port_header"
        },
        {
            "name": "port_header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "$output"
        },
EOF
		)

		# Check Http2
		if [ "$http2" == "yes" ]; then
			json+=$(
				cat <<EOF

        {
            "name": "pbclient",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "$domain",
                "port": $remote_port,
                "path": "/",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
EOF
			)
		else
			if [ "$PreConnect" == "yes" ]; then
				json+=$(
					cat <<EOF

        {
            "name": "precon_client",
            "type": "PreConnectClient",
            "settings": {
                "minimum-unused": $min_un
            },
            "next": "sslclient"
        },
EOF
				)
			fi
		fi

		if [ "$http2" == "yes" ]; then
			alpn="h2"
		else
			alpn="http/1.1"
		fi

		json+=$(
			cat <<EOF

        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "$domain",
                "verify": true,
                "alpn":"$alpn"
            },
            "next": "output"
        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	# Function to create tls multi port kharej
	create_tls_multi_port_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local (${yellow}Connection${green}) port: ${rest}"
		read -r local_port
		echo -en "${green}Do you want to Enable Http2 ? (yes/no) [${yellow}Default: yes${green}] : ${rest}"
		read -r http2
		http2=${http2:-yes}

		if [ "$http2" == "yes" ]; then
			output="h2server"
		else
			output="port_header"
		fi

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "tls_multiport_kharej",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "sslserver"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallback-intence-delay":0
            },
            "next": "$output"
        },
EOF
		)

		if [ "$http2" == "yes" ]; then
			json+=$(
				cat <<EOF

		{
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "pbserver"
        },
        {
            "name": "pbserver",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "port_header"
        },
EOF
			)
		fi

		json+=$(
			cat <<EOF

	{
            "name":"port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "output"
        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address":"127.0.0.1",
                "port":"dest_context->port"
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
	}

	echo -e "${yellow}      *******************************${rest}"
	echo -e "${yellow}      |${purple} [1]${green} Tls port to port Iran${yellow}   |${rest}"
	echo -e "${yellow}      |${purple} [2]${green} Tls port to port kharej${yellow} |${rest}"
	echo -e "${yellow}      |${blue}*****************************${yellow}|${rest}"
	echo -e "${yellow}      |${purple} [3]${green} Tls Multiport iran${yellow}      |${rest}"
	echo -e "${yellow}      |${purple} [4]${green} Tls Multiport kharej${yellow}    |${rest}"
	echo -e "${yellow}      |${blue}*****************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple} [0]${green} ${green}Back to ${purple}Main Menu${yellow}      |${rest}"
	echo -e "${yellow}      *******************************${rest}"
	echo -en "${cyan}      Enter your choice (1-4): ${rest}"
	read -r choice

	case $choice in
	1)
		create_tls_port_to_port_iran
		waterwall_service
		;;
	2)
		create_tls_port_to_port_kharej
		waterwall_service
		;;
	3)
		create_tls_multi_port_iran
		waterwall_service
		;;
	4)
		create_tls_multi_port_kharej
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================

#3
# Reverse Tunnel
reverse() {
	create_reverse_tls_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local (${yellow}Client Config${green}) port: ${rest}"
		read -r local_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote (${yellow}Connection${green}) port: ${rest}"
		read -r remote_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reverse_tls_iran",
    "nodes": [
        {
            "name": "users_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next":  "bridge2"
        },      
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }         
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "kharej_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $remote_port,
                "nodelay": true,
                "whitelist":[
                    "$remote_address/32"
                ]
            },
            "next": "reverse_server"
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
		echo ""
	}

	create_reverse_tls_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local (${yellow}Server Config${green}) port: ${rest}"
		read -r local_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote (${yellow}Connection${green}) port: ${rest}"
		read -r remote_port
		echo -en "${green}Enter Minimum-unused [${yellow}Default: 16${green}]: ${rest}"
		read -r min_un
		min_un=${min_un:-16}

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reverse_tls_kharej",
    "nodes": [
        {
            "name": "outbound_to_core",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address":"127.0.0.1",
                "port":$local_port
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "outbound_to_core"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
                "minimum-unused": $min_un
            },
            "next":  "outbound_to_iran"
        },
        {
            "name": "outbound_to_iran",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address":"$remote_address",
                "port":$remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_reverse_tls_h2_multi_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote port: ${rest}"
		read -r remote_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reverse_tls_h2_multi_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "header"
        },
        {
            "name": "header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "pbserver",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "pbserver"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallback-intence-delay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_server_kharej",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $remote_port,
                "nodelay": true,
                "whitelist": [
                    "$remote_address/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
		echo ""
	}

	create_reverse_tls_h2_multi_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter Your Domain: ${rest}"
		read -r domain
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote port: ${rest}"
		read -r remote_port
		echo -en "${green}Enter Minimum-unused [${yellow}Default: 16${green}]: ${rest}"
		read -r min_un
		min_un=${min_un:-16}

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reverse_tls_h2_multi_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "header"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
                "minimum-unused": $min_un
            },
            "next": "pbclient"
        },
        {
            "name": "pbclient",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "$domain",
                "port": $remote_port,
                "path": "/",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "$domain",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	echo -e "${yellow}      **************************************${rest}"
	echo -e "${yellow}      |${purple} [1] ${green}Reveres Tls port to port Iran${yellow}  |${rest}"
	echo -e "${yellow}      |${purple} [2] ${green}Reveres Tls port to port kharej${yellow}|${rest}"
	echo -e "${yellow}      |${blue}************************************${yellow}|${rest}"
	echo -e "${yellow}      |${purple} [3] ${green}Reveres Tls Multiport Iran${yellow}     |${rest}"
	echo -e "${yellow}      |${purple} [4] ${green}Reveres Tls Multiport kharej${yellow}   |${rest}"
	echo -e "${yellow}      |${blue}************************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple} [0] ${green}Back to ${purple}Main Menu${yellow}             |${rest}"
	echo -e "${yellow}      **************************************${rest}"
	echo -en "${cyan}      Enter your choice (1-2): ${rest}"
	read -r choice

	case $choice in
	1)
		create_reverse_tls_iran
		waterwall_service
		;;
	2)
		create_reverse_tls_kharej
		waterwall_service
		;;
	3)
		create_reverse_tls_h2_multi_iran
		waterwall_service
		;;
	4)
		create_reverse_tls_h2_multi_kharej
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================
#4
# Reality Direct Tunnel
direct_reality() {
	create_reality_client_multiport_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter SNI (${yellow}Example: google.com${green}): ${rest}"
		read -r sni
		echo -en "${green}Enter a password (${yellow}same password on both servers${green}): ${rest}"
		read -r passwd

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reality_client_multiport",
    "nodes": [
        {
            "name": "users_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "header"
        },
        {
            "name": "header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "my_reality_client"
        },
        {
            "name": "my_reality_client",
            "type": "RealityClient",
            "settings": {
                "sni": "$sni",
                "password": "$passwd"
            },
            "next": "outbound_to_kharej"
        },
        {
            "name": "outbound_to_kharej",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": 443
            }
        }
    ]
}
EOF
		)

		echo "$json" >/root/Waterwall/config.json
	}

	create_reality_client_multiport_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -e "${yellow}This method uses port 443. Make sure it is not already in use and is open. ${rest}"
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter a password (${yellow}same password on both servers${green}): ${rest}"
		read -r passwd
		echo -en "${green}Enter SNI (${yellow}Example: google.com${green}): ${rest}"
		read -r sni

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reality_server_multiport",
    "nodes": [
        {
            "name": "main_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true
            },
            "next": "my_reality_server"
        },
        {
            "name": "my_reality_server",
            "type": "RealityServer",
            "settings": {
                "destination": "reality_dest_node",
                "password": "$passwd"
            },
            "next": "header_server"
        },
        {
            "name": "header_server",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "final_outbound"
        },
        {
            "name": "final_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "reality_dest_node",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$sni",
                "port": 443
            }
        }
    ]
}
EOF
		)

		echo "$json" >/root/Waterwall/config.json
	}

	echo -e "${yellow}      *******************************${rest}"
	echo -e "${yellow}      |${purple} [1] ${green}Reality Multiport Iran${yellow}  |${rest}"
	echo -e "${yellow}      |${purple} [2] ${green}Reality Multiport kharej${yellow}|${rest}"
	echo -e "${yellow}      |${blue}*****************************${yellow}|${rest}"
	echo -e "${yellow}      |${purple}  [0] ${green}Back to ${purple}Main Menu${yellow}      |${rest}"
	echo -e "${yellow}      *******************************${rest}"
	echo -en "${cyan}      Enter your choice (1-2): ${rest}"
	read -r choice

	case $choice in
	1)
		create_reality_client_multiport_iran
		waterwall_service
		;;
	2)
		create_reality_client_multiport_kharej
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================
#5
# Reality Reverse Tunnel
reality_reverse() {
	create_reverse_reality_server_multiport_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter SNI (${yellow}Example: google.com${green}): ${rest}"
		read -r sni
		echo -en "${green}Enter a password (${yellow}same password on both servers${green}): ${rest}"
		read -r passwd

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reverse_reality_server_multiport",
    "nodes": [
        {
            "name": "users_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "header"
        },
        {
            "name": "header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "reality_server",
            "type": "RealityServer",
            "settings": {
                "destination": "reality_dest",
                "password": "$passwd"
            },
            "next": "reverse_server"
        },
        {
            "name": "kharej_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "$remote_address/32"
                ]
            },
            "next": "reality_server"
        },
        {
            "name": "reality_dest",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$sni",
                "port": 443
            }
        }
    ]
}
EOF
		)

		echo "$json" >/root/Waterwall/config.json
	}

	create_reverse_reality_client_multiport_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -e "${yellow}This method uses port 443. Make sure it is not already in use and is open. ${rest}"
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter SNI (${yellow}Example: google.com${green}): ${rest}"
		read -r sni
		echo -en "${green}Enter a password (${yellow}same password on both servers${green}): ${rest}"
		read -r passwd
		echo -en "${green}Enter Minimum-unused [${yellow}Default: 16${green}]: ${rest}"
		read -r min_un
		min_un=${min_un:-16}

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "reverse_reality_client_multiport",
    "nodes": [
        {
            "name": "outbound_to_core",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "outbound_to_core"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "header"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
                "minimum-unused": $min_un
            },
            "next": "reality_client"
        },
        {
            "name": "reality_client",
            "type": "RealityClient",
            "settings": {
                "sni": "$sni",
                "password": "$passwd"
            },
            "next": "outbound_to_iran"
        },
        {
            "name": "outbound_to_iran",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": 443
            }
        }
    ]
}
EOF
		)

		echo "$json" >/root/Waterwall/config.json
	}

	echo -e "${yellow}      ***************************************${rest}"
	echo -e "${yellow}      |${purple} [1] ${green}Reverse Reality Multiport Iran${yellow}  |${rest}"
	echo -e "${yellow}      |${purple} [2] ${green}Reverse Reality Multiport kharej${yellow}|${rest}"
	echo -e "${yellow}      |${blue}*************************************${yellow}|${rest}"
	echo -e "${yellow}      |${purple}  [0] ${green}Back to ${purple}Main Menu${yellow}              |${rest}"
	echo -e "${yellow}      ***************************************${rest}"
	echo -en "${cyan}      Enter your choice (1-2): ${rest}"
	read -r choice

	case $choice in
	1)
		create_reverse_reality_server_multiport_iran
		waterwall_service
		;;
	2)
		create_reverse_reality_client_multiport_kharej
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================

#6
# Bgp4 Tunnel
bgp4() {
	create_bgp4_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local port: ${rest}"
		read -r local_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote (${yellow}Connection${green}) port [${yellow}Default: 179${green}]: ${rest}"
		read -r remote_port
		remote_port=${remote_port:-179}

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "bgp_client",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "bgp_client"
        },
        {
            "name": "bgp_client",
            "type": "Bgp4Client",
            "settings": {},
            "next": "output"
        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_bgp4_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local (${yellow}Connection${green}) port [${yellow}Default: 179${green}]: ${rest}"
		read -r local_port
		local_port=${local_port:-179}
		echo -en "${green}Enter the remote (${yellow}Server Config ${green}) port: ${rest}"
		read -r remote_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "bgp_server",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "bgp_server"
        },
        {
            "name": "bgp_server",
            "type": "Bgp4Server",
            "settings": {},
            "next": "output"
        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_bgp4_multiport_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port
		echo -en "${green}Enter the remote address: ${rest}"
		read -r remote_address
		echo -en "${green}Enter the remote (${yellow}Connection${green}) port [${yellow}Default: 179${green}]: ${rest}"
		read -r remote_port
		remote_port=${remote_port:-179}

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "bgp_Multiport_client",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "port_header"
        },
        {
            "name": "port_header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bgp_client"
        },
        {
            "name": "bgp_client",
            "type": "Bgp4Client",
            "settings": {},
            "next": "output"
        }, 
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$remote_address",
                "port": $remote_port
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_bgp4_multiport_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local (${yellow}Connection${green}) port [${yellow}Default: 179${green}]: ${rest}"
		read -r local_port
		local_port=${local_port:-179}

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "bgp_Multiport_server",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "bgp_server"
        },
        {
            "name": "bgp_server",
            "type": "Bgp4Server",
            "settings": {},
            "next": "port_header"
        },
        {
            "name":"port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "output"

        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	echo -e "${yellow}      ********************************${rest}"
	echo -e "${yellow}      | ${purple}[1]${green} bgp4 port to port Iran${yellow}   |${rest}"
	echo -e "${yellow}      | ${purple}[2]${green} bgp4 port to port kharej${yellow} |${rest}"
	echo -e "${yellow}      |${blue}******************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple}[3]${green} bgp4 Multiport Iran${yellow}      |${rest}"
	echo -e "${yellow}      | ${purple}[4]${green} bgp4 Multiport kharej${yellow}    |${rest}"
	echo -e "${yellow}      |${blue}******************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple} [0] ${green}Back to ${purple}Main Menu${yellow}       |${rest}"
	echo -e "${yellow}      ********************************${rest}"
	echo -en "${cyan}      Enter your choice (1-2): ${rest}"
	read -r choice

	case $choice in
	1)
		create_bgp4_iran
		waterwall_service
		;;
	2)
		create_bgp4_kharej
		waterwall_service
		;;
	3)
		create_bgp4_multiport_iran
		waterwall_service
		;;
	4)
		create_bgp4_multiport_kharej
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================

#7
#Trojan Direct
trojan_config() {
	# Check if the  trojan directory exists
	if [ ! -d /root/Waterwall/trojan ]; then
		mkdir -p /root/Waterwall/trojan
	fi

	# Function to create direct Trojan configuration
	create_direct_trojan() {
		if sudo systemctl is-active --quiet trojan.service; then
			echo -e "${cyan}============================${rest}"
			echo -e "${green}Trojan is already installed${rest}"
			echo -e "${cyan}============================${rest}"
			return 0
		else
			echo -e "${cyan}============================${rest}"
			echo -en "${green}Enter Your Domain: ${rest}"
			read -r domain
			echo -en "${green}Enter a port [${yellow}Default: 443${green}]: ${rest}"
			read -r local_port
			local_port=${local_port:-443}
			echo -en "${green}Enter a name for user: ${rest}"
			read -r user
			echo -en "${green}Enter uuid (Password): ${rest}"
			read -r passwd
			echo -en "${green}Enter Tls fallback Address [${yellow}Default: demo.nginx.com${green}]: ${rest}"
			read -r tls_fall
			tls_fall=${tls_fall:-demo.nginx.com}
			echo -en "${green}Enter trojan fallback Address [${yellow}Default: httpforever.com${green}]: ${rest}"
			read -r trojan_fall
			trojan_fall=${trojan_fall:-httpforever.com}

			# Install Waterwall
			install_waterwall

			# Trojan configuration JSON
			json=$(
				cat <<EOF
{
    "name": "direct_trojan",
    "nodes": [
        {
            "name": "my-tcp-listener",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "my-ssl-server"
        },
        {
            "name": "my-ssl-server",
            "type": "OpenSSLServer",
            "settings": {
                "anti-tls-in-tls": true,
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallback": "my-tls-fallback"
            },
            "next": "my-trojan-auth"
        },
        {
            "name": "my-trojan-auth",
            "type": "TrojanAuthServer",
            "settings": {
                "fallback": "my-trojan-fallback",
                "fallback-intence-delay": 200,
                "users": [
                    {
                        "name": "$user",
                        "uid": "$passwd",
                        "enable": true
                    }
                ]
            },
            "next": "my-trojan-socks"
        },
        {
            "name": "my-trojan-socks",
            "type": "TrojanSocksServer",
            "settings": {},
            "next": "my-connector"
        },
        {
            "name": "my-connector",
            "type": "Connector",
            "settings": {
                "nodelay": true,
                "address": "dest_context->address",
                "port": "dest_context->port"
            }
        },
        {
            "name": "my-tls-fallback",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "${tls_fall}",
                "port": 443
            }
        },
        {
            "name": "my-trojan-fallback",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "${trojan_fall}",
                "port": 80
            }
        }
    ]
}
EOF
			)

			# Write JSON to config file
			echo "$json" >/root/Waterwall/trojan/trojan_config.json

			trojan_service

			# Generate Trojan URL
			T_config="trojan://$passwd@$domain:$local_port?security=tls&alpn=h2,http/1.1&headerType=none&fp=chrome&type=tcp&sni=$domain#Trojan_Waterwall"

			# Output Trojan URL
			echo -e "${cyan}============================${rest}"
			echo -e "${purple}1) ${cyan}Copy Config to ${yellow}V2rayNG${rest}"
			echo ""
			echo -e "${yellow} $T_config${rest}"
			echo ""
			echo -e "${purple}2) ${cyan}If you haven't already.Run the script again and get the ${red}SSL Certificate ${cyan}for your ${yellow}domain${rest}"
			echo -e "${cyan}============================${rest}"
		fi
	}

	# Function to add user to Trojan configuration
	add_user() {
		if [ -f ~/Waterwall/trojan/trojan_config.json ]; then
			# Display current list of users with their index numbers
			echo -e "${cyan}============================${rest}"
			echo -e "${cyan}Current list of users:${rest}"
			jq -r '.nodes[2].settings.users | to_entries[] | "\(.key + 1). \(.value.name) (\(.value.uid))"' ~/Waterwall/trojan/trojan_config.json
			echo -e "${cyan}============================${rest}"
			echo -en "${green}Enter a name for new user: ${rest}"
			read -r user
			echo -en "${green}Enter uuid (Password): ${rest}"
			read -r passwd
			# Add the new user to config.json using jq
			jq ".nodes[2].settings.users += [{\"name\": \"$user\", \"uid\": \"$passwd\", \"enable\": true}]" ~/Waterwall/trojan/trojan_config.json >~/Waterwall/temp.json && mv ~/Waterwall/temp.json ~/Waterwall/trojan/trojan_config.json
			echo -e "${cyan}============================${rest}"
			echo -e "${green}User ${cyan}$user ${green}Added successfully. ${rest}"
			echo -e "${cyan}============================${rest}"
			sudo systemctl restart trojan.service >/dev/null 2>&1
		else
			echo -e "${cyan}============================${rest}"
			echo -e "${red}Install Trojan Config first${rest}"
			echo -e "${cyan}============================${rest}"
		fi
	}

	# Function to delete user from Trojan configuration
	del_user() {
		if [ -f ~/Waterwall/trojan/trojan_config.json ]; then
			echo -e "${cyan}============================${rest}"
			# Display current list of users with their index numbers
			echo -e "${cyan}Current list of users:${rest}"
			jq -r '.nodes[2].settings.users | to_entries[] | "\(.key + 1). \(.value.name) (\(.value.uid))"' ~/Waterwall/trojan/trojan_config.json

			# Ask user to enter the index number of the user to delete
			echo -e "${cyan}============================${rest}"
			echo -en "${green}Enter the number of the user to delete: ${rest}"
			read -r index

			# Check if the input index is valid
			num_users=$(jq '.nodes[2].settings.users | length' ~/Waterwall/trojan/trojan_config.json)
			if [[ "$index" -ge 1 && "$index" -le "$num_users" ]]; then
				# Delete the user by index
				jq "del(.nodes[2].settings.users[$index - 1])" ~/Waterwall/trojan/trojan_config.json >~/Waterwall/temp.json && mv ~/Waterwall/temp.json ~/Waterwall/trojan/trojan_config.json
				echo -e "${cyan}============================${rest}"
				echo -e "${green}User ${cyan}$index${green} has been deleted.${rest}"
				echo -e "${cyan}============================${rest}"
				sudo systemctl restart trojan.service >/dev/null 2>&1
			else
				echo -e "${red}Invalid number. Please enter a valid number.${rest}"
			fi
		else
			echo -e "${cyan}============================${rest}"
			echo -e "${red}Install Trojan Config first${rest}"
			echo -e "${cyan}============================${rest}"
		fi
	}

	# Uninstall Trojan
	uninstall_trojan() {
		if [ -f ~/Waterwall/trojan/config.json ] || systemctl is-active --quiet trojan.service; then
			echo -e "${cyan}============================${rest}"
			echo -en "${green}Do you want to delete the Certificates as well? (yes/no): ${rest}"
			read -r delete_cert

			if [[ "$delete_cert" == "yes" ]]; then
				echo -e "${cyan}============================${rest}"
				echo -en "${green}Enter Your domain: ${rest}"
				read -r domain

				rm -rf ~/.acme.sh/"${domain}"_ecc
				rm -rf ~/Waterwall/cert
				echo -e "${green}Certificate for ${domain} has been deleted.${rest}"
			fi

			rm -rf ~/Waterwall/trojan
			systemctl stop trojan.service >/dev/null 2>&1
			systemctl disable trojan.service >/dev/null 2>&1
			echo -e "${cyan}============================${rest}"
			echo -e "${green}Trojan has been uninstalled successfully.${rest}"
			echo -e "${cyan}============================${rest}"
		else
			echo -e "${cyan}============================${rest}"
			echo -e "${red}Trojan is not installed.${rest}"
			echo -e "${cyan}============================${rest}"
		fi
	}

	echo -e "${yellow}      ***************************${rest}"
	echo -e "${yellow}      |${purple} [1]${green} Install Trojan${yellow}      |${rest}"
	echo -e "${yellow}      |${purple} [2]${green} Add user${yellow}            |${rest}"
	echo -e "${yellow}      |${purple} [3]${green} Del user${yellow}            |${rest}"
	echo -e "${yellow}      |${purple} [4]${green} Uninstall Trojan${yellow}    |${rest}"
	echo -e "${yellow}      |${blue}*************************${yellow}|${rest}"
	echo -e "${yellow}      |${purple}  [0] ${green}Back to ${purple}Main Menu${yellow}  |${rest}"
	echo -e "${yellow}      ***************************${rest}"
	echo -en "${cyan}      Enter your choice (1-3): ${rest}"
	read -r choice

	case $choice in
	1)
		create_direct_trojan
		;;
	2)
		add_user
		;;
	3)
		del_user
		;;
	4)
		uninstall_trojan
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================

#8
#Reverse CDN Tunnel
reverse_cdn() {
	create_reverse_tls_grpc_singleport_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local port: ${rest}"
		read -r local_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "config_reverse_tls_grpc_singleport_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": $local_port,
                "nodelay": true
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "grpc_server",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "grpc_server"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallback-intence-delay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_cloudflare",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                    "108.162.192.0/18",
                    "190.93.240.0/20",
                    "188.114.96.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                    "162.158.0.0/15",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "172.64.0.0/13",
                    "131.0.72.0/22",
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                    "2a06:98c0::/29",
                    "2c0f:f248::/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${blue}1) ${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
		echo -e "${blue}2) ${yellow}Enable [grpc] in CloudFlare Network Setting${rest}"
		echo -e "${blue}3) ${yellow}Enable Minimum TLS Version [TlS 1.2] in CloudFlare Edge Certificate Setting${rest}"
		echo -e "${blue}4) ${yellow}Enable [Proxy status] in CloudFlare Dns Record Setting${rest}"
		echo -e "${blue}5) ${yellow}Wait at least 5 minutes to apply Changes in CloudFlare${rest}"
		echo -e "${cyan}============================${rest}"
	}

	create_reverse_tls_grpc_singleport_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter your remote domain: ${rest}"
		read -r domain
		echo -en "${green}Enter the local (${yellow}Config${green}) port: ${rest}"
		read -r local_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "config_reverse_tls_grpc_singleport_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": $local_port
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
            },
            "next": "grpc_client"
        },
        {
            "name": "grpc_client",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "$domain",
                "port": 443,
                "path": "/service",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "$domain",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$domain",
                "port": 443
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_reverse_tls_grpc_multiport_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter your remote domain: ${rest}"
		read -r domain

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "config_reverse_tls_grpc_multiport_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "port_header"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
            },
            "next": "grpc_client"
        },
        {
            "name": "grpc_client",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "$domain",
                "port": 443,
                "path": "/service",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "$domain",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$domain",
                "port": 443
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_reverse_tls_grpc_multiport_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "config_reverse_tls_grpc_multiport_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "port_header"
        },
        {
            "name": "port_header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "grpc_server",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "grpc_server"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallback-intence-delay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_cloudflare",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                    "108.162.192.0/18",
                    "190.93.240.0/20",
                    "188.114.96.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                    "162.158.0.0/15",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "172.64.0.0/13",
                    "131.0.72.0/22",
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                    "2a06:98c0::/29",
                    "2c0f:f248::/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${blue}1) ${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
		echo -e "${blue}2) ${yellow}Enable [grpc] in CloudFlare Network Setting${rest}"
		echo -e "${blue}3) ${yellow}Enable Minimum TLS Version [TlS 1.2] in CloudFlare Edge Certificate Setting${rest}"
		echo -e "${blue}4) ${yellow}Enable [Proxy status] in CloudFlare Dns Record Setting${rest}"
		echo -e "${blue}5) ${yellow}Wait at least 5 minutes to apply Changes in CloudFlare${rest}"
		echo -e "${cyan}============================${rest}"
	}

	create_reverse_tls_grpc_multiport_hd_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the starting local port [${yellow}greater than 23${green}]: ${rest}"
		read -r start_port
		echo -en "${green}Enter the ending local port [${yellow}less than 65535${green}]: ${rest}"
		read -r end_port

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "config_reverse_tls_grpc_multiport_hd_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [$start_port,$end_port],
                "nodelay": true
            },
            "next": "port_header"
        },
        {
            "name": "port_header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "halfs",
            "type": "HalfDuplexServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "grpc_server",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "halfs"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "grpc_server"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "/root/Waterwall/cert/fullchain.pem",
                "key-file": "/root/Waterwall/cert/privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallback-intence-delay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_cloudflare",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                    "108.162.192.0/18",
                    "190.93.240.0/20",
                    "188.114.96.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                    "162.158.0.0/15",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "172.64.0.0/13",
                    "131.0.72.0/22",
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                    "2a06:98c0::/29",
                    "2c0f:f248::/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
		echo -e "${blue}1) ${yellow}If you haven't already, you should get [SSL CERTIFICATE] for your domain in the main menu.${rest}"
		echo -e "${blue}2) ${yellow}Enable [grpc] in CloudFlare Network Setting${rest}"
		echo -e "${blue}3) ${yellow}Enable Minimum TLS Version [TlS 1.2] in CloudFlare Edge Certificate Setting${rest}"
		echo -e "${blue}4) ${yellow}Enable [Proxy status] in CloudFlare Dns Record Setting${rest}"
		echo -e "${blue}5) ${yellow}Wait at least 5 minutes to apply Changes in CloudFlare${rest}"
		echo -e "${cyan}============================${rest}"
	}

	create_reverse_tls_grpc_multiport_hd_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter your remote domain: ${rest}"
		read -r domain

		install_waterwall

		json=$(
			cat <<EOF
{
    "name": "config_reverse_tls_grpc_multiport_hd_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "port_header"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
            },
            "next": "halfc"
        },
        {
            "name": "halfc",
            "type": "HalfDuplexClient",
            "settings": {},
            "next": "grpc_client"
        },
        {
            "name": "grpc_client",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "$domain",
                "port": 443,
                "path": "/service",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "$domain",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "$domain",
                "port": 443
            }
        }
    ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	echo -e "${yellow}      *******************************************${rest}"
	echo -e "${yellow}      | ${purple}[1]${green} Reverse tls grpc singleport iran${yellow}    |${rest}"
	echo -e "${yellow}      | ${purple}[2]${green} Reverse tls grpc singleport kharej${yellow}  |${rest}"
	echo -e "${yellow}      |${blue}*****************************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple}[3]${green} Reverse tls grpc Multiport iran${yellow}     |${rest}"
	echo -e "${yellow}      | ${purple}[4]${green} Reverse tls grpc Multiport kharej${yellow}   |${rest}"
	echo -e "${yellow}      |${blue}*****************************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple}[5]${green} Reverse tls grpc Multiport HD iran${yellow}  |${rest}"
	echo -e "${yellow}      | ${purple}[6]${green} Reverse tls grpc Multiport HD kharej${yellow}|${rest}"
	echo -e "${yellow}      |${blue}*****************************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple} [0] ${green}Back to ${purple}Main Menu${yellow}                  |${rest}"
	echo -e "${yellow}      *******************************************${rest}"
	echo -en "${cyan}      Enter your choice (1-2): ${rest}"
	read -r choice

	case $choice in
	1)
		create_reverse_tls_grpc_singleport_iran
		waterwall_service
		;;
	2)
		create_reverse_tls_grpc_singleport_kharej
		waterwall_service
		;;
	3)
		create_reverse_tls_grpc_multiport_iran
		waterwall_service
		;;
	4)
		create_reverse_tls_grpc_multiport_kharej
		waterwall_service
		;;
	5)
		create_reverse_tls_grpc_multiport_hd_iran
		waterwall_service
		;;
	6)
		create_reverse_tls_grpc_multiport_hd_kharej
		waterwall_service
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================
# Reset Iptables rules
reset_iptables() {
	echo -e "${cyan}============================${rest}"
	echo -en "${green}Press Enter to Reset Iptables rules [required]: ${rest}"
	read -r
	echo -e "${green}Resetting iptables rules to default settings...${rest}"
	echo -e "${cyan}============================${rest}"

	sudo iptables -P INPUT ACCEPT
	sudo iptables -P FORWARD ACCEPT
	sudo iptables -P OUTPUT ACCEPT

	sudo iptables -F
	sudo iptables -X
	sudo iptables -Z
	sudo iptables -t nat -F
	sudo iptables -t nat -X
	sudo iptables -t mangle -F
	sudo iptables -t mangle -X
	sudo iptables -t raw -F
	sudo iptables -t raw -X

	echo -e "${green}Iptables rules have been successfully reset.${rest}"
	echo -e "${cyan}============================${rest}"
}

# My IP
ip_address=$(hostname -I | awk '{print $1}' || curl -s https://api64.ipify.org)

# Check firewall status
ufw() {
	if sudo ufw status | grep -q "Status: active"; then
		echo -e "${cyan}============================${rest}"
		echo -e "${green}The firewall is active.${rest}"
		echo -en "${green}Press Enter to disable it [required]: ${rest}"
		read -r
		sudo ufw disable
	fi
}

#9
# Reset Tunnel
reset_tunnel() {
	create_reset_tunnel_iran() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local IP address $ip_address: ${rest}"
		read -r server_ip
		server_ip="${server_ip:-$ip_address}"
		echo -en "${green}Enter the remote IP address: ${rest}"
		read -r remote_address
		ufw
		reset_iptables
		install_waterwall

		json=$(
			cat <<EOF
{
  "name": "reset_tunnel_iran",
  "nodes": [
    {
      "name": "input",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        "port": [
          23,
          65535
        ],
        "nodelay": true
      },
      "next": "output"
    },
    {
      "name": "output",
      "type": "TcpConnector",
      "settings": {
        "nodelay": true,
        "address": "10.0.0.2",
        "port": "src_context->port"
      }
    },
    {
      "name": "tdev",
      "type": "TunDevice",
      "settings": {
        "device-name": "tun0",
        "device-ip": "10.0.0.1/24"
      }
    },
    {
      "name": "rdev",
      "type": "RawDevice",
      "settings": {
        "mode": "injector"
      }
    },
    {
      "name": "cdev",
      "type": "CaptureDevice",
      "settings": {
        "direction": "incoming",
        "filter-mode": "source-ip",
        "ip": "$remote_address/32"
      }
    },
    {
      "name": "route1_receiver",
      "type": "Layer3Receiver",
      "settings": {
        "device": "tdev"
      },
      "next": "route1_source_changer"
    },
    {
      "name": "route1_source_changer",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "source-ip",
        "ipv4": "$server_ip"
      },
      "next": "tcp_reset_on"
    },
    {
      "name": "tcp_reset_on",
      "type": "Layer3TcpManipulator",
      "settings": {
        "bit-reset": "on"
      },
      "next": "route1_dest_setter"
    },
    {
      "name": "route1_dest_setter",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "dest-ip",
        "ipv4": "$remote_address"
      },
      "next": "route1_writer"
    },
    {
      "name": "route1_writer",
      "type": "Layer3Sender",
      "settings": {
        "device": "rdev"
      }
    },
    {
      "name": "route2_receiver",
      "type": "Layer3Receiver",
      "settings": {
        "device": "cdev"
      },
      "next": "route2_source_changer"
    },
    {
      "name": "route2_source_changer",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "source-ip",
        "ipv4": "10.0.0.2"
      },
      "next": "tcp_reset_off"
    },
    {
      "name": "tcp_reset_off",
      "type": "Layer3TcpManipulator",
      "settings": {
        "bit-reset": "off"
      },
      "next": "route2_dest_setter"
    },
    {
      "name": "route2_dest_setter",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "dest-ip",
        "ipv4": "10.0.0.1"
      },
      "next": "route2_writer"
    },
    {
      "name": "route2_writer",
      "type": "Layer3Sender",
      "settings": {
        "device": "tdev"
      }
    }
  ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	create_reset_tunnel_kharej() {
		echo -e "${cyan}============================${rest}"
		echo -en "${green}Enter the local IP address $ip_address: ${rest}"
		read -r server_ip
		server_ip="${server_ip:-$ip_address}"
		echo -en "${green}Enter the remote IP address: ${rest}"
		read -r remote_address
		ufw
		reset_iptables

		install_waterwall

		json=$(
			cat <<EOF
{
  "name": "reset_tunnel_kharej",
  "nodes": [
    {
      "name": "tdev",
      "type": "TunDevice",
      "settings": {
        "device-name": "tun0",
        "device-ip": "10.0.0.1/24"
      }
    },
    {
      "name": "rdev",
      "type": "RawDevice",
      "settings": {
        "mode": "injector"
      }
    },
    {
      "name": "cdev",
      "type": "CaptureDevice",
      "settings": {
        "direction": "incoming",
        "filter-mode": "source-ip",
        "ip": "$remote_address/32"
      }
    },
    {
      "name": "route1_receiver",
      "type": "Layer3Receiver",
      "settings": {
        "device": "tdev"
      },
      "next": "route1_source_changer"
    },
    {
      "name": "route1_source_changer",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "source-ip",
        "ipv4": "$server_ip"
      },
      "next": "tcp_reset_on"
    },
    {
      "name": "tcp_reset_on",
      "type": "Layer3TcpManipulator",
      "settings": {
        "bit-reset": "on"
      },
      "next": "route1_dest_setter"
    },
    {
      "name": "route1_dest_setter",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "dest-ip",
        "ipv4": "$remote_address"
      },
      "next": "route1_writer"
    },
    {
      "name": "route1_writer",
      "type": "Layer3Sender",
      "settings": {
        "device": "rdev"
      }
    },
    {
      "name": "route2_receiver",
      "type": "Layer3Receiver",
      "settings": {
        "device": "cdev"
      },
      "next": "route2_source_changer"
    },
    {
      "name": "route2_source_changer",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "source-ip",
        "ipv4": "10.0.0.2"
      },
      "next": "tcp_reset_off"
    },
    {
      "name": "tcp_reset_off",
      "type": "Layer3TcpManipulator",
      "settings": {
        "bit-reset": "off"
      },
      "next": "route2_dest_setter"
    },
    {
      "name": "route2_dest_setter",
      "type": "Layer3IpOverrider",
      "settings": {
        "mode": "dest-ip",
        "ipv4": "10.0.0.1"
      },
      "next": "route2_writer"
    },
    {
      "name": "route2_writer",
      "type": "Layer3Sender",
      "settings": {
        "device": "tdev"
      }
    }
  ]
}
EOF
		)
		echo "$json" >/root/Waterwall/config.json
	}

	echo -e "${yellow}      *************************************${rest}"
	echo -e "${yellow}      | ${purple}[1]${green} Reset Tunnel Multiport Iran${yellow}   |${rest}"
	echo -e "${yellow}      | ${purple}[2]${green} Reset Tunnel Multiport kharej${yellow} |${rest}"
	echo -e "${yellow}      |${blue}***********************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple}[3]${green} Reset Iptables Rules${yellow}          |${rest}"
	echo -e "${yellow}      |${blue}***********************************${yellow}|${rest}"
	echo -e "${yellow}      | ${purple} [0] ${green}Back to ${purple}Main Menu${yellow}            |${rest}"
	echo -e "${yellow}      *************************************${rest}"
	echo -en "${cyan}      Enter your choice (1-3): ${rest}"
	read -r choice

	case $choice in
	1)
		create_reset_tunnel_iran
		waterwall_service
		;;
	2)
		create_reset_tunnel_kharej
		waterwall_service
		;;
	3)
		reset_iptables
		;;
	0)
		main
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
#===================================
#10
# Custom Config
custom() {
	# Ask user to enter JSON input
	echo -e "${cyan}============================================${rest}"
	echo -en "${green}Enter Your Config Name [${yellow}Default: config.json${green}]: ${rest}"
	read -r config
	config=${config:-config.json}
	config_path="/root/Waterwall/${config}"

	# Check if file already exists
	if [ -e "$config_path" ]; then
		echo -en "${yellow}Warning: File $config_path already exists. Do you want to overwrite it? [y/N]: ${rest}"
		read -r overwrite
		if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
			echo -e "${red}Exiting without saving.${rest}"
			exit 1
		fi
	fi

	echo -en "${green}Please enter your JSON input. Press Ctrl+D when finished:${rest}"

	# Read JSON input from user
	json_input=$(cat)

	install_waterwall

	# Validate if JSON input is not empty
	if [ -z "$json_input" ]; then
		echo -e "${red}Error: JSON input is empty. Exiting...${rest}"
		exit 1
	fi

	# Save JSON input to config file
	if echo "$json_input" >"$config_path"; then
		echo -e "${green}JSON successfully saved to $config_path.${rest}"
	else
		echo -e "${cyan}==============================================${rest}"
		echo -e "${red}Error: Failed to save JSON to $config_path.${rest}"
		exit 1
	fi
	echo ""

	waterwall_service
}
#===================================

# Uninstall Waterwall
uninstall_waterwall() {
	if [ -f ~/Waterwall/config.json ] || [ -f /etc/systemd/system/Waterwall.service ]; then
		echo -e "${cyan}==============================================${rest}"
		echo -en "${green}Press Enter to continue, or Ctrl+C to cancel.${rest}"
		read -r
		if [ -d ~/Waterwall/cert ] || [ -f ~/.acme/acme.sh ]; then
			echo -e "${cyan}============================${rest}"
			echo -en "${green}Do you want to delete the Domain Certificates? (yes/no): ${rest}"
			read -r delete_cert

			if [[ "$delete_cert" == "yes" ]]; then
				echo -e "${cyan}============================${rest}"
				echo -en "${green}Enter Your domain: ${rest}"
				read -r domain

				rm -rf ~/.acme.sh/"${domain}"_ecc
				rm -rf ~/Waterwall/cert
				echo -e "${green}Certificate for ${domain} has been deleted.${rest}"
			fi
		fi

		rm -rf ~/Waterwall/{core.json,config.json,Waterwall,log/}
		systemctl stop Waterwall.service >/dev/null 2>&1
		systemctl disable Waterwall.service >/dev/null 2>&1
		rm -rf /etc/systemd/system/Waterwall.service >/dev/null 2>&1
		echo -e "${cyan}============================${rest}"
		echo -e "${green}Waterwall has been uninstalled successfully.${rest}"
		echo -e "${cyan}============================${rest}"
	else
		echo -e "${cyan}============================${rest}"
		echo -e "${red}Waterwall is not installed.${rest}"
		echo -e "${cyan}============================${rest}"
	fi
}
#===================================

# Create Service
waterwall_service() {
	create_core_json
	# Create a new service
	cat <<EOL >/etc/systemd/system/Waterwall.service
[Unit]
Description=Waterwall Tunnel Service
After=network.target

[Service]
Type=idle
User=root
WorkingDirectory=/root/Waterwall
ExecStart=/root/Waterwall/Waterwall
Restart=always

[Install]
WantedBy=multi-user.target
EOL

	# Reload systemctl daemon and start the service
	sudo systemctl daemon-reload
	sudo systemctl restart Waterwall.service >/dev/null 2>&1
	check_waterwall_status
}
#===================================

# Trojan Service
trojan_service() {
	create_trojan_core_json
	# Create Trojan service
	cat <<EOL >/etc/systemd/system/trojan.service
[Unit]
Description=Waterwall Trojan Service
After=network.target

[Service]
Type=idle
User=root
WorkingDirectory=/root/Waterwall/trojan
ExecStart=/root/Waterwall/Waterwall
Restart=always

[Install]
WantedBy=multi-user.target
EOL

	# Reload systemctl daemon and start the service
	sudo systemctl daemon-reload
	sudo systemctl restart trojan.service >/dev/null 2>&1
}
#===================================
# Check Install service
check_install_service() {
	if [ -f /etc/systemd/system/Waterwall.service ]; then
		echo -e "${cyan}===================================${rest}"
		echo -e "${red}Please uninstall the existing Waterwall service before continuing.${rest}"
		echo -e "${cyan}===================================${rest}"
		exit 1
	fi
}
#===================================
# Check tunnel status
check_tunnel_status() {
	# Check the status of the tunnel service
	if sudo systemctl is-active --quiet Waterwall.service; then
		echo -e "${yellow}     Waterwall :${green} [running ✔] ${rest}"
	else
		echo -e "${yellow}     Waterwall: ${red} [Not running ✗ ] ${rest}"
	fi
}
#===================================
# Check Waterwall status
check_waterwall_status() {
	sleep 1
	# Check the status of the tunnel service
	if sudo systemctl is-active --quiet Waterwall.service; then
		echo -e "${cyan}Waterwall Installed successfully :${green} [running ✔] ${rest}"
		echo -e "${cyan}============================================${rest}"
	else
		echo -e "${yellow}Waterwall is not installed or ${red}[Not running ✗ ] ${rest}"
		echo -e "${cyan}==============================================${rest}"
	fi
}
#===================================

# Check Trojan status
check_trojan_status() {
	# Check the status of the tunnel service
	if sudo systemctl is-active --quiet trojan.service; then
		echo -e "${yellow}     Trojan :${green}    [running ✔] ${rest}"
	else
		echo -e "${yellow}     Trojan: ${red}    [Not running ✗ ] ${rest}"
	fi
}
#===================================

# Main Menu
main() {
	clear
	echo -e "${cyan}By --> Peyman * Github.com/Ptechgithub *${rest}"
	echo ""
	check_tunnel_status
	check_trojan_status
	echo -e "${yellow}***********************************${rest}"
	echo -e "${yellow}*${green} github.com/${cyan}radkesvat${green}/WaterWall ${yellow} *${rest}"
	echo -e "${yellow}***********************************${rest}"
	echo -e "${yellow}*${green} [${cyan}1${green}] Simple Tunnel ${yellow}              *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}2${green}] Tls Tunnel${yellow}                  *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}3${green}] Reverse Tunnel${yellow}              *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}4${green}] Reality Direct Tunnel${yellow}       *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}5${green}] Reality Reverse Tunnel${yellow}      *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}6${green}] Bgp4 Tunnel${yellow}                 *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}7${green}] Trojan Config${yellow}               *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}8${green}] Reverse CDN Tunnel${yellow}          *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}9${green}] Reset Tunnel${yellow}                *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}10${green}] Install Custom${yellow}             *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}11${green}] SSL Certificate Management${yellow} *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green} [${cyan}12${green}] Uninstall Waterwall${yellow}        *${rest}"
	echo -e "${yellow}*                                 *${rest}"
	echo -e "${yellow}*${green}  [${purple}0${green}] ${purple}Exit${yellow}                       *${rest}"
	echo -e "${yellow}***********************************${rest}"

	echo -en "${cyan}Enter your choice (1-12): ${rest}"
	read -r choice

	case $choice in
	1)
		check_install_service
		simple_direct
		;;
	2)
		check_install_service
		tls
		;;
	3)
		check_install_service
		reverse
		;;
	4)
		check_install_service
		direct_reality
		;;
	5)
		check_install_service
		reality_reverse
		;;
	6)
		check_install_service
		bgp4
		;;
	7)
		trojan_config
		;;
	8)
		check_install_service
		reverse_cdn
		;;
	9)
		reset_tunnel
		;;
	10)
		custom
		;;
	11)
		ssl_cert_issue_main
		;;
	12)
		uninstall_waterwall
		;;
	0)
		echo -e "${cyan}good bye 🖐${rest}"
		exit
		;;
	*)
		echo -e "${red}Invalid choice!${rest}"
		;;
	esac
}
main
