#include "mainwindow.h"
#include <QApplication>

#include <iostream>
#include <fstream>
#include <sys/utsname.h>

#include <unistd.h>

#include <iostream>
#include <memory>
#include <map>
#include <sstream>

#include <QRegularExpression>
#include <QString>

#//ip
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>

//interface name
#include <iostream>
#include <sys/types.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

typedef struct {
    int physicalId;
    int core;
    int clock;
} CpuInfo;

std::string getArch()
{
    struct utsname buffer;
    if (uname(&buffer) != 0) {
        return "";
    }
    return buffer.machine;
}

void getHostName(std::string &hostname)
{
    char hostname_[HOST_NAME_MAX];
    gethostname(hostname_, HOST_NAME_MAX);
    hostname = std::string(hostname_);
}

int getOSName(std::string & os)
{
    std::ifstream osRelease("/etc/os-release");
    std::string line;
    if (!osRelease.is_open())
        return -1;
    size_t pos;
    while (std::getline(osRelease, line)) {
        if ((pos = line.find("PRETTY_NAME")) != std::string::npos)
        {
            break;
        }
    }
    osRelease.close();
    //PRETTY_NAME="Kylin V10"
    std::string substr = line.substr(12);
    pos = 0;
    while((pos = substr.find('"')) != std::string::npos){substr.erase(pos,1);}
    os = substr;
    return 0;
}

std::string execCmd(const char*cmd)
{
    std::array<char, 256>buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed.");
    }
    while(fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int getDiskDeviceName(std::vector<std::string> &devices)
{
    QString result = QString::fromStdString(execCmd("LANG=en lsblk -P -o NAME,TYPE |grep disk"));
    QStringList results = result.split("\n", QString::SkipEmptyParts);
    for (const QString & result : results) {
        QStringList parts = result.split(QRegularExpression("\\s+"), QString::SkipEmptyParts);
        for (const QString& part : parts) {
            if (part.contains("NAME", Qt::CaseInsensitive)) {
                std::string name = part.mid(part.indexOf('=')+1).remove(QRegularExpression("[\"]")).toStdString();
                devices.push_back(name);
            }
        }
    }
}

std::string getDiskSerialNumber(const std::string &device)
{
    std::string serialNumber;
    std::string cmd = "udevadm info --query=all --name=/dev/" + device + "| grep ID_SERIAL_SHORT=";
    std::string result = execCmd(cmd.c_str());
    if (!result.empty()) {
        size_t pos = result.find("ID_SERIAL_SHORT=");
        if (pos != std::string::npos) {
            serialNumber = result.substr(pos + 16);
            //remove trailing newline character
            serialNumber.pop_back();
        }
    } else {
        throw std::runtime_error("Failed to get serial number for device");
    }
    return serialNumber;
}

double getDiskSize(const std::string &device)
{
    std::string sizefile = "/sys/block/" + device + "/size";
    std::ifstream file(sizefile);
    double size = 0;
    if (file.is_open()) {
        file >> size;
        //size is in 512-byte sectors,convert to bytes
        size *= 512;
        //convert to human readable Gigabytes
        size = size / (1024*1024*1024);
    } else {
        throw std::runtime_error("Failed to open " + sizefile);
    }
    return size;
}

int getCPUInfo(std::map <int, CpuInfo> &cpuInfo)
{
    std::ifstream file("/proc/cpuinfo");
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open /proc/cpuinfo");
        return -1;
    }
    CpuInfo tmpCpuInfo;
    tmpCpuInfo.physicalId = -1;
    tmpCpuInfo.core = -1;
    tmpCpuInfo.clock = -1;

    std::string line;
    int curPhysicalId = -1;
    int logicalCoreCount = 0;
    while (std::getline(file, line)) {
        std::istringstream is(line);
        std::string key;
        if (std::getline(is, key, ':')) {
            std::string value;
            if (std::getline(is, value) && !value.empty()) {
                key = key.substr(0, key.find_last_not_of(" \t") + 1);
                value = value.substr(value.find_first_not_of(" \t"));
                if (key == "physical id") {
                    tmpCpuInfo.physicalId = std::stoi(value);
                } else if (key == "cpu cores") {
                    tmpCpuInfo.core = std::stoi(value);
                } else if (key == "cpu MHz") {
                    tmpCpuInfo.clock = std::stoi(value);
                }
            }
        }
        if (tmpCpuInfo.physicalId != -1 && tmpCpuInfo.core != -1 && tmpCpuInfo.clock != -1) {
            cpuInfo[tmpCpuInfo.physicalId] = tmpCpuInfo;
            tmpCpuInfo.physicalId = -1;
            tmpCpuInfo.core = -1;
            tmpCpuInfo.clock = -1;
        }
    }
    return 0;
}

int getIPAddress(std::string & ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        return 1;
    }
    const char* google_dns_server = "8.8.8.8";
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, google_dns_server, &addr.sin_addr);
    // Connect to Google DNS
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        close(sock);
        return 1;
    }
    // Get local address bound to the socket
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sock, (struct sockaddr *)&local_addr, &addr_len);
    char ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, ip_addr, INET_ADDRSTRLEN);
    ip = ip_addr;
    close(sock);
    return 0;
}

bool getInterfaceSubnetMask(const char *ifname, std::string &netmask) {
    int sockfd;
    struct ifreq ifr;
    char ip[INET_ADDRSTRLEN];
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return false;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) {
        close(sockfd);
        return false;
    }
    netmask = ip;
    close(sockfd);
    return true;
}



std::string getInterfaceNameForIP(const char* ip) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    std::string interface_name;

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Error in getifaddrs" << std::endl;
        return "";
    }

    // Walk through linked list, maintaining head pointer so we can free list later
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
            if (s != 0) {
                std::cerr << "getnameinfo() failed: " << gai_strerror(s) << std::endl;
                continue;
            }

            if (strcmp(host, ip) == 0) {
                interface_name = ifa->ifa_name;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return interface_name;
}

bool getMAC(const char *ifname, std::string & macAddress) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return false;
    }
    macAddress = ifr.ifr_hwaddr.sa_data;
    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    macAddress = mac;
    close(sockfd);
    return true;
}

std::string getGateway(const std::string& interface) {
    std::ifstream route_file("/proc/net/route");
    std::string line;
    std::string gateway;

    if (route_file.is_open()) {
        while (std::getline(route_file, line)) {
            std::istringstream iss(line);
            std::vector<std::string> tokens{std::istream_iterator<std::string>{iss},
                                            std::istream_iterator<std::string>{}};

            if (tokens.size() >= 3 && tokens[0] == interface && tokens[1] == "00000000") {
                std::stringstream ss;
                ss << std::hex << tokens[2];
                unsigned long gw;
                ss >> gw;

                struct in_addr addr;
                addr.s_addr = gw;

                gateway = inet_ntoa(addr);
                break;
            }
        }
        route_file.close();
    }
    return gateway;
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
#if 0
    std::string os;
    getOSName(os);
    std::cerr << "os: " << os << std::endl;

    std::string hostname;
    getHostName(hostname);
    std::cerr << "HostName: " << hostname << std::endl;
    try {
        std::map <int, CpuInfo> cpuInfo;
        getCPUInfo(cpuInfo);
        for (const auto & item : cpuInfo) {
            std::cout << "key: " << item.first << " " << "clock: " << item.second.clock << "core: " << item.second.core << std::endl;
        }
    } catch (const std::exception & e) {
        std::cerr << e.what() << std::endl;
    }
#else
    std::string ip;
    getIPAddress(ip);
    std::cout << "IP Address: " << ip << std::endl;

    std::string interface_name = getInterfaceNameForIP(ip.c_str());
    if (interface_name.empty()) {
        std::cout << "Error retrieving interface name." << std::endl;
    } else {
        std::cout << "interface_name: " << interface_name << std::endl;
    }

    std::cout << "gateway: "<< getGateway(interface_name) << std::endl;

    std::string mac;
    getMAC(interface_name.c_str(), mac);
    std::cout << "Mac: " << mac << std::endl;

    std::string netmask;
    getInterfaceSubnetMask(interface_name.c_str(), netmask);
    std::cout << "netmask: " << netmask << std::endl;

#endif
    return 0;
}
