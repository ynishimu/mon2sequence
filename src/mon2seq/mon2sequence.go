package mon2seq

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Peer struct {
	Type string
	IP   string
}

const maxPacket = 200

var hostnames map[string]string = make(map[string]string)
var peerList []Peer = []Peer{}
var globalHost string = "myhost"

func Monparse(myHost string, monlog_path string) (returnFile string) {
	var monStart bool
	var ifilter bool
	var jfilter bool
	var i, j = 0, 0 //i:packet#, j:line#
	var DNS [][]string
	var dns1 string
	var nascode int = 0 // 0: not processed 1: next is message 2: complete
	var outbound bool
	//if myHost == "" {
	//	myHost = "myhost"
	//}
	myHost = globalHost
	var outbuf bytes.Buffer
	hostnames = make(map[string]string)
	var myhostList = []string{}
	peerList = []Peer{}

	timeStampBuf := ""
	timeStampBuf2 := ""
	badWordBuf := ""
	hexDumpBuf := ""
	messageBuf := ""
	Type := ""
	Hosts := make([][]string, 2)
	sequence := ""
	node := []string{myHost}

	//output file. For local test, change it to ./
	diagFile, err := ioutil.TempFile("/tmp/", "mon2seq*.txt")
	if err != nil {
		fmt.Println(err)
	}
	diagfile_path := diagFile.Name()

	regexMon := "(Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday) (January|February|March|April|May|Jun|July|August|September|October|November|December) [0-3][0-9] 20[0-9][0-9]"
	rem, err := regexp.Compile(regexMon)
	regexAddr := "([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|([0-9a-fA-F]{1,4}:)[0-9a-fA-F:]{0,30}:[0-9a-fA-F]{1,4})|Local Disk"
	rea, err := regexp.Compile(regexAddr)
	regexType := "(GTP|Diameter|PFCP|RADIUS|CDR|DNS|NAS|S1AP)"
	ret, err := regexp.Compile(regexType)
	regexBadWord := "(x-|-x)"
	reb, err := regexp.Compile(regexBadWord)
	regexHexDump := "(PDU HEX DUMP|^0x0000	)"
	reh, err := regexp.Compile(regexHexDump)
	regexGtp := "(^.* Message [Tt]ype: )|(.*$)"
	regtp, err := regexp.Compile(regexGtp)
	regexTime := "([0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9][0-9])"
	regtm, err := regexp.Compile(regexTime)
	regexDiamCode := "(\\([0-9]+\\) .*)"
	rediam, err := regexp.Compile(regexDiamCode)

	fmt.Println("mon2seq starting")

	if err != nil {
		panic(err)
	}

	file, _ := os.Open(monlog_path)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		timeStampBuf = rem.FindString(scanner.Text())
		badWordBuf = reb.FindString(scanner.Text())
		hexDumpBuf = reh.FindString(scanner.Text())
		if !monStart {
			// Found Tuesday March 31 2020
			if len(timeStampBuf) != 0 {
				monStart = true
				i = 1
				j = 1
			}
		} else {
			// End of packet
			if len(timeStampBuf) != 0 || strings.Contains(scanner.Text(), "Call Finished") {
				if !ifilter {
					//result := " No." + strconv.Itoa(i) + "\\n" + " " + timeStampBuf2 + "\n" + sequence + "\n" + messageBuf
					result := " " + timeStampBuf2 + " [" + strconv.Itoa(i) + "] " + "\n" + sequence + "\n" + messageBuf
					//output(result, diagfile_path)
					outbuf.WriteString(result)
					messageBuf = ""
					ifilter = false
					jfilter = false
					i += 1
					j = 1
					nascode = 0
				} else {
					messageBuf = ""
					ifilter = false
					jfilter = false
					j = 1
				}
				// Need to replace bad chars
			} else if len(badWordBuf) != 0 {
				m1 := strings.Replace(scanner.Text(), "-", "_", -1)
				messageBuf += "#" + m1 + "\n"
				j += 1
			} else if len(hexDumpBuf) != 0 {
				jfilter = true
			} else {
				if jfilter {
					j += 1000
				} else {
					messageBuf += "#" + scanner.Text() + "\n"
					j += 1
				}
			}
		}
		if j == 2 {
			timeStampBuf2 = regtm.FindString(scanner.Text())
			if strings.Contains(scanner.Text(), "<<<<") {
				outbound = true
			} else if strings.Contains(scanner.Text(), ">>>>") {
				outbound = false
			} else {
				ifilter = true
				j = 1000
			}
		}
		if j == 3 {
			Type = ret.FindString(scanner.Text())
			if Type != "DNS" {
				Hosts = rea.FindAllStringSubmatch(scanner.Text(), -1)
				if outbound {
					host := strings.Replace(Hosts[0][0], ":", "-", -1)
					if Type == "PFCP" || Type == "GTP" || Type == "S1AP" || Type == "NAS" {
						if strings.LastIndex(host, "-") != -1 {
							host = host[:strings.LastIndex(host, "-")]
						}
					}
					myhostList = append(myhostList, host)
					Hosts[0][0] = myHost
					Hosts[1][0] = strings.Replace(Hosts[1][0], ":", "-", -1)
				} else {
					host := strings.Replace(Hosts[1][0], ":", "-", -1)
					if Type == "PFCP" || Type == "GTP" || Type == "S1AP" || Type == "NAS" {
						if strings.LastIndex(host, "-") != -1 {
							host = host[:strings.LastIndex(host, "-")]
						}
					}
					myhostList = append(myhostList, host)
					Hosts[1][0] = myHost
					Hosts[0][0] = strings.Replace(Hosts[0][0], ":", "-", -1)
				}
				node = removeDuplicate1(node)
			}
		}
		if j == 4 {
			if Type == "PFCP" || Type == "GTP" {
				if strings.LastIndex(Hosts[0][0], "-") != -1 {
					Hosts[0][0] = Hosts[0][0][:strings.LastIndex(Hosts[0][0], "-")]
				}
				if strings.LastIndex(Hosts[1][0], "-") != -1 {
					Hosts[1][0] = Hosts[1][0][:strings.LastIndex(Hosts[1][0], "-")]
				}
				node = append(node, Hosts[0][0])
				node = append(node, Hosts[1][0])
				node = removeDuplicate1(node)
				Hosts[0][0] = addr2nodename(Hosts[0][0], node, Type)
				Hosts[1][0] = addr2nodename(Hosts[1][0], node, Type)
				m1 := Hosts[0][0] + "->" + Hosts[1][0] + ":"
				m2 := regtp.FindAllStringSubmatch(scanner.Text(), -1)
				sequence = m1 + m2[1][0]
			} else if Type == "RADIUS" {
				node = append(node, Hosts[0][0])
				node = append(node, Hosts[1][0])
				node = removeDuplicate1(node)
				Hosts[0][0] = addr2nodename(Hosts[0][0], node, Type)
				Hosts[1][0] = addr2nodename(Hosts[1][0], node, Type)
				m1 := Hosts[0][0] + "->" + Hosts[1][0] + ":"
				m2 := scanner.Text()[strings.Index(scanner.Text(), "(")+1 : strings.Index(scanner.Text(), ")")]
				sequence = m1 + m2
			} else if Type == "CDR" {
				node = append(node, Hosts[0][0])
				node = append(node, Hosts[1][0])
				node = removeDuplicate1(node)
				Hosts[0][0] = addr2nodename(Hosts[0][0], node, Type)
				Hosts[1][0] = addr2nodename(Hosts[1][0], node, Type)
				m1 := Hosts[0][0] + "->" + Hosts[1][0] + ":"
				m2 := strings.Replace(scanner.Text(), "Message Type: ", "", 1)
				sequence = m1 + m2
			} else if Type == "DNS" {
				if !outbound {
					DNS = rea.FindAllStringSubmatch(scanner.Text(), -1)
				}
			}
		}
		if j == 5 {
			if Type == "DNS" {
				if outbound {
					DNS = rea.FindAllStringSubmatch(scanner.Text(), -1)
					node = append(node, DNS[0][0])
					node = removeDuplicate1(node)
					DNS[0][0] = addr2nodename(DNS[0][0], node, Type)
					dns1 = myHost + "->" + DNS[0][0] + ":"
				} else {
					node = append(node, DNS[0][0])
					node = removeDuplicate1(node)
					DNS[0][0] = addr2nodename(DNS[0][0], node, Type)
					dns1 = DNS[0][0] + "->" + myHost + ":"
				}
				sequence = dns1
			}
		}
		if j == 8 {
			if Type == "DNS" {
				dns2 := scanner.Text()[strings.Index(scanner.Text(), ":")+1:]
				sequence += "DNS: " + dns2
			}
			if Type == "Diameter" {
				node = append(node, Hosts[0][0])
				node = append(node, Hosts[1][0])
				node = removeDuplicate1(node)
				Hosts[0][0] = addr2nodename(Hosts[0][0], node, Type)
				Hosts[1][0] = addr2nodename(Hosts[1][0], node, Type)
				m1 := Hosts[0][0] + "->" + Hosts[1][0] + ":"
				m2 := rediam.FindString(scanner.Text())
				if m2 == "" {
					m2 = strings.Replace(scanner.Text(), "Command Code: ", "", 1)
				}
				sequence = m1 + strings.TrimSpace(m2)
			}
			if Type == "S1AP" {
				if strings.LastIndex(Hosts[0][0], "-") != -1 {
					Hosts[0][0] = Hosts[0][0][:strings.LastIndex(Hosts[0][0], "-")]
				}
				if strings.LastIndex(Hosts[1][0], "-") != -1 {
					Hosts[1][0] = Hosts[1][0][:strings.LastIndex(Hosts[1][0], "-")]
				}
				node = append(node, Hosts[0][0])
				node = append(node, Hosts[1][0])
				node = removeDuplicate1(node)
				Hosts[0][0] = addr2nodename(Hosts[0][0], node, Type)
				Hosts[1][0] = addr2nodename(Hosts[1][0], node, Type)
				m1 := Hosts[0][0] + "->" + Hosts[1][0] + ":"
				m2 := strings.Replace(scanner.Text(), "Procedure Code :", "", 1)
				sequence = m1 + strings.TrimSpace(m2)
			}
		}
		// Special handling for NAS, as NAS message line is random
		if Type == "NAS" {
			switch nascode {
			case 0: // not processed yet
				if strings.Contains(scanner.Text(), "Message Type") {
					nascode = 1
				}
			case 1: // next is NAS message
				if strings.LastIndex(Hosts[0][0], "-") != -1 {
					Hosts[0][0] = Hosts[0][0][:strings.LastIndex(Hosts[0][0], "-")]
				}
				if strings.LastIndex(Hosts[1][0], "-") != -1 {
					Hosts[1][0] = Hosts[1][0][:strings.LastIndex(Hosts[1][0], "-")]
				}
				node = append(node, Hosts[0][0])
				node = append(node, Hosts[1][0])
				node = removeDuplicate1(node)
				Hosts[0][0] = addr2nodename(Hosts[0][0], node, Type)
				Hosts[1][0] = addr2nodename(Hosts[1][0], node, Type)
				m1 := Hosts[0][0] + "->" + Hosts[1][0] + ":"
				sequence = m1 + strings.TrimSpace(scanner.Text())
				nascode = 2
			default:
			}
		}
		if i == maxPacket {
			fmt.Println("Reached max number of packets: %d", maxPacket)
			break
		}
	}
	myhostList = removeDuplicate1(myhostList)
	outbufStr := replaceMyhost(outbuf.String(), myhostList, myHost)
	genHostnames(myhostList, myHost)
	title := "title " + monlog_path[strings.LastIndex(monlog_path, "/")+1:] + "\n"
	result := title + genParticipants(myHost, hostnames) + outbufStr
	file, err2 := os.OpenFile(diagfile_path, os.O_WRONLY|os.O_CREATE, 0666)
	if err2 != nil {
		fmt.Println(err2)
	}
	defer file.Close()
	fmt.Fprintln(file, result)
	fmt.Println("mon2seq ending")
	return diagfile_path
}

func genHostnames(myhostList []string, myhost string) {
	var newPeerList = []Peer{}
	var isMyhost = false
	for _, p := range peerList {
		for _, h := range myhostList {
			if p.IP == h {
				isMyhost = true
			}
		}
		if p.IP != myhost && !isMyhost {
			newPeerList = append(newPeerList, p)
		}
		isMyhost = false
	}
	for i := 0; i < len(newPeerList); i++ {
		host := strconv.Itoa(i+1) + "-" + newPeerList[i].Type
		hostnames[host] = newPeerList[i].Type + "-" + newPeerList[i].IP
	}
}

func replaceMyhost(outbufStr string, myhostList []string, myhost string) string {
	for _, h := range myhostList {
		//outbufStr = strings.Replace(outbufStr, "->"+h+":", "->"+myhost+":", -1)
		//outbufStr = strings.Replace(outbufStr, h+"->", myhost+"->", -1)
		rep1 := regexp.MustCompile("\\->.+" + h + ":")
		rep2 := regexp.MustCompile(".+" + h + "\\->")
		outbufStr = rep1.ReplaceAllString(outbufStr, "->"+myhost+":")
		outbufStr = rep2.ReplaceAllString(outbufStr, myhost+"->")
	}
	return outbufStr
}

func removeDuplicate1(node []string) []string {
	results := make([]string, 0, len(node))
	encountered := map[string]bool{}
	for i := 0; i < len(node); i++ {
		if !encountered[node[i]] {
			encountered[node[i]] = true
			results = append(results, node[i])
		}
	}
	return results
}

func addr2nodename(host string, node []string, proto string) string {
	hostip := host
	if proto == "NAS" || proto == "S1AP" {
		proto = "ENB"
	}
	for i := 1; i < len(node); i++ {
		if host == node[i] {
			if len(proto) > 0 {
				host = strconv.Itoa(i) + "-" + proto
			} else {
				proto = "Node"
				host = strconv.Itoa(i) + "-Node"
			}
		}
	}
	tmpPeer := Peer{proto, hostip}
	if contains(peerList, tmpPeer) == false {
		peerList = append(peerList, tmpPeer)
	}
	if hostip == globalHost {
		return hostip
	} else {
		return proto + "-" + hostip
	}
}

func genParticipants(myhost string, node map[string]string) string {
	var participants bytes.Buffer
	participants.WriteString("participant " + myhost + " as " + myhost + "\n")
	delete(node, myhost)
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, n := range keys {
		participants.WriteString("participant " + n + " as " + node[n] + "\n")
	}
	return participants.String() + "\n"
}

func unset(s []Peer, i int) []Peer {
	if i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}
func contains(s []Peer, e Peer) bool {
	for _, v := range s {
		if e.Type == v.Type && e.IP == v.IP {
			return true
		}
	}
	return false
}
