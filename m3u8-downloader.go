// @author:llychao<lychao_vip@163.com>
// @contributor: Junyi<me@junyi.pw>
// @date:2020-02-18
// @功能:golang m3u8 video Downloader
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/levigross/grequests"
)

const (
	// HEAD_TIMEOUT 请求头超时时间
	HEAD_TIMEOUT = 10 * time.Second
	// PROGRESS_WIDTH 进度条长度
	PROGRESS_WIDTH = 20
	// TS_NAME_TEMPLATE ts视频片段命名规则
	TS_NAME_TEMPLATE = "%05d.ts"
)

var (
	// 命令行参数
	urlFlag = flag.String("u", "", "m3u8下载地址(http(s)://url/xx/xx/index.m3u8)")
	nFlag   = flag.Int("n", 16, "下载线程数(max goroutines num)")
	htFlag  = flag.String("ht", "apiv1", "设置getHost的方式(apiv1: `http(s):// + url.Host + filepath.Dir(url.Path)`; apiv2: `http(s)://+ u.Host`")
	oFlag   = flag.String("o", "movie", "自定义文件名(默认为movie)")
	cFlag   = flag.String("c", "", "自定义请求 cookie")
	sFlag   = flag.Int("s", 0, "是否允许不安全的请求(默认为0)")
	spFlag  = flag.String("sp", "", "文件保存路径(默认为当前路径)")
	fFlag   = flag.String("f", "", "自定义m3u8文件")
	hFlag   = flag.String("h", "", "自定义host，配合 -f 使用")
	kFlag   = flag.String("k", "", "自定义m3u8的aes key解密文件，不指定则默认走m3u8文件定义的key")
	mFlag   = flag.String("m", "", "合并指定文件夹下所有的ts文件片段")
	pFlag   = flag.String("p", "", "指定socks/http代理")

	logger *log.Logger
	ro     = &grequests.RequestOptions{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36",
		RequestTimeout: HEAD_TIMEOUT,
		Headers: map[string]string{
			"Connection":      "keep-alive",
			"Accept":          "*/*",
			"Accept-Encoding": "*",
			"Accept-Language": "zh-CN,zh;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
		},
	}

	proxy *url.URL
)

// TsInfo 用于保存 ts 文件的下载地址和文件名
type TsInfo struct {
	Name string
	Url  string
}

func init() {
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	Run()
}

func Run() {
	msgTpl := "[功能]:多线程下载直播流 m3u8 视屏（ts + 合并）\n[提醒]:如果下载失败，请使用 -ht=apiv2 \n[提醒]:如果下载失败，m3u8 地址可能存在嵌套\n[提醒]:如果进度条中途下载失败，可重复执行"
	fmt.Println(msgTpl)
	runtime.GOMAXPROCS(runtime.NumCPU())
	now := time.Now()

	// 解析命令行参数
	flag.Parse()
	m3u8Url := *urlFlag
	maxGoroutines := *nFlag
	hostType := *htFlag
	movieDir := *oFlag
	cookie := *cFlag
	insecure := *sFlag
	savePath := *spFlag

	if *mFlag != "" {
		Merge(*mFlag)
		return
	}

	if (!strings.HasPrefix(m3u8Url, "http") || m3u8Url == "") && *fFlag == "" {
		flag.Usage()
		return
	}

	var err error
	proxy, err = url.Parse(*pFlag)
	if err != nil {
		fmt.Println("代理地址解析失败：" + err.Error())
		os.Exit(-1)
	}

	ro.Headers["Referer"] = getHost(m3u8Url, "apiv2")
	if insecure != 0 {
		ro.InsecureSkipVerify = true
	}
	// http 自定义 cookie
	if cookie != "" {
		ro.Headers["Cookie"] = cookie
	}

	var downloadDir string
	pwd, _ := os.Getwd()
	if savePath != "" {
		pwd = savePath
	}
	// pwd = "/Users/chao/Desktop" //自定义地址
	downloadDir = filepath.Join(pwd, movieDir)
	if isExist, _ := pathExists(downloadDir); !isExist {
		os.MkdirAll(downloadDir, os.ModePerm)
	}
	m3u8Host := getHost(m3u8Url, hostType)
	m3u8Body := getM3u8Body(m3u8Url)
	// m3u8Body := getFromFile()
	tsKey := getM3u8Key(m3u8Host, m3u8Body)
	if tsKey != "" {
		fmt.Printf("待解密 ts 文件 key : %s \n", tsKey)
	}
	tsList := getTsList(m3u8Host, m3u8Body)
	fmt.Println("待下载 ts 文件数量:", len(tsList))
	// 下载ts
	downloader(tsList, maxGoroutines, downloadDir, tsKey)
	Merge(downloadDir)
	fmt.Printf("\n[Success] 下载保存路径：%s | 共耗时: %6.2fs\n", downloadDir+".mp4", time.Now().Sub(now).Seconds())
}

func Merge(path string) {
	if ok := checkTsDownDir(path); !ok {
		fmt.Printf("\n[Failed] 请检查url地址有效性 \n")
		return
	}
	switch runtime.GOOS {
	case "windows":
		win_merge_file(path)
	default:
		unix_merge_file(path)
	}
	os.Rename(filepath.Join(path, "merge.mp4"), path+".mp4")
	os.RemoveAll(path)
	DrawProgressBar("Merging", float32(1), PROGRESS_WIDTH, "merge.ts")
}

// 获取m3u8地址的host
func getHost(Url, ht string) (host string) {
	// 解析本地m3u8文件时，由用户传入host
	if *hFlag != "" {
		return *hFlag
	}

	if Url == "" {
		return ""
	}

	u, err := url.Parse(Url)
	checkErr(err)
	switch ht {
	case "apiv1":
		host = u.Scheme + "://" + u.Host + filepath.Dir(u.EscapedPath())
	case "apiv2":
		host = u.Scheme + "://" + u.Host
	}
	return
}

// 获取m3u8地址的内容体
func getM3u8Body(Url string) string {
	// 如果指定m3u8本地文件，则直接解析本地文件
	if *fFlag != "" {
		return getM3u8BodyLocal()
	}
	r, err := grequests.Get(Url, ro)
	checkErr(err)
	return r.String()
}

// 获取本地m3u8文件的内容体
func getM3u8BodyLocal() string {
	byt, err := ioutil.ReadFile(*fFlag)
	if err != nil {
		fmt.Println("读取本地m3u8文件失败，err:" + err.Error())
		os.Exit(-1)
	}
	return string(byt)
}

// 获取m3u8加密的密钥
func getM3u8Key(host, html string) (key string) {
	// 如果指定 m3u8 key 本地文件，则直接解析本地文件
	if *kFlag != "" {
		return getM3u8KeyLocal()
	}
	lines := strings.Split(html, "\n")
	key = ""
	for _, line := range lines {
		if strings.Contains(line, "#EXT-X-KEY") {
			uri_pos := strings.Index(line, "URI")
			quotation_mark_pos := strings.LastIndex(line, "\"")
			key_url := strings.Split(line[uri_pos:quotation_mark_pos], "\"")[1]
			if !strings.Contains(line, "http") {
				key_url = fmt.Sprintf("%s/%s", host, key_url)
			}
			res, err := grequests.Get(key_url, ro)
			checkErr(err)
			if res.StatusCode == 200 {
				key = res.String()
			}
		}
	}
	return
}

func getM3u8KeyLocal() (key string) {
	file, err := ioutil.ReadFile(*kFlag)
	if err != nil {
		fmt.Println("读取本地 m3u8 key 文件失败，err:" + err.Error())
		os.Exit(-1)
	}
	return string(file)
}

func getTsList(host, body string) (tsList []TsInfo) {
	lines := strings.Split(body, "\n")
	index := 0
	var ts TsInfo
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" {
			// 有可能出现的二级嵌套格式的m3u8,请自行转换！
			index++
			if strings.HasPrefix(line, "http") {
				ts = TsInfo{
					Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
					Url:  line,
				}
				tsList = append(tsList, ts)
			} else {
				ts = TsInfo{
					Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
					Url:  fmt.Sprintf("%s/%s", host, line),
				}
				tsList = append(tsList, ts)
			}
		}
	}
	return
}

func getFromFile() string {
	data, _ := ioutil.ReadFile("./ts.txt")
	return string(data)
}

// 下载ts文件
// @modify: 2020-08-13 修复ts格式SyncByte合并不能播放问题
func downloadTsFile(ts TsInfo, download_dir, key string, retries int) {
	defer func() {
		if r := recover(); r != nil {
			// fmt.Println("网络不稳定，正在进行断点持续下载")
			downloadTsFile(ts, download_dir, key, retries-1)
		}
	}()
	curr_path := fmt.Sprintf("%s/%s", download_dir, ts.Name)
	if isExist, _ := pathExists(curr_path); isExist {
		// logger.Println("[warn] File: " + ts.Name + "already exist")
		return
	}
	// 增加代理
	u, err := url.Parse(ts.Url)
	if err != nil {
		fmt.Println("解析 ts url +" + ts.Url + "失败")
		os.Exit(-1)
	}
	ro.Proxies[u.Scheme] = proxy

	res, err := grequests.Get(ts.Url, ro)
	if err != nil || !res.Ok {
		if retries > 0 {
			downloadTsFile(ts, download_dir, key, retries-1)
			return
		} else {
			// logger.Printf("[warn] File :%s", ts.Url)
			return
		}
	}
	// 校验长度是否合法
	var origData []byte
	origData = res.Bytes()
	contentLen := 0
	contentLenStr := res.Header.Get("Content-Length")
	if contentLenStr != "" {
		contentLen, _ = strconv.Atoi(contentLenStr)
	}
	if len(origData) == 0 || (contentLen > 0 && len(origData) < contentLen) || res.Error != nil {
		// logger.Println("[warn] File: " + ts.Name + "res origData invalid or err：", res.Error)
		downloadTsFile(ts, download_dir, key, retries-1)
		return
	}
	// 解密出视频 ts 源文件
	if key != "" {
		// 解密 ts 文件，算法：aes 128 cbc pack5
		origData, err = AesDecrypt(origData, []byte(key))
		if err != nil {
			downloadTsFile(ts, download_dir, key, retries-1)
			return
		}
	}
	// https://en.wikipedia.org/wiki/MPEG_transport_stream
	// Some TS files do not start with SyncByte 0x47, they can not be played after merging,
	// Need to remove the bytes before the SyncByte 0x47(71).
	syncByte := uint8(71) // 0x47
	bLen := len(origData)
	for j := 0; j < bLen; j++ {
		if origData[j] == syncByte {
			origData = origData[j:]
			break
		}
	}
	ioutil.WriteFile(curr_path, origData, 0666)
}

// downloader m3u8 下载器
func downloader(tsList []TsInfo, maxGoroutines int, downloadDir string, key string) {
	retry := 5 // 单个 ts 下载重试次数
	var wg sync.WaitGroup
	limiter := make(chan struct{}, maxGoroutines) // chan struct 内存占用 0 bool 占用 1
	tsLen := len(tsList)
	downloadCount := 0
	for _, ts := range tsList {
		wg.Add(1)
		limiter <- struct{}{}
		go func(ts TsInfo, downloadDir, key string, retryies int) {
			defer func() {
				wg.Done()
				<-limiter
			}()
			downloadTsFile(ts, downloadDir, key, retryies)
			downloadCount++
			DrawProgressBar("Downloading", float32(downloadCount)/float32(tsLen), PROGRESS_WIDTH, ts.Name)
			return
		}(ts, downloadDir, key, retry)
	}
	wg.Wait()
}

func checkTsDownDir(dir string) bool {
	if isExist, _ := pathExists(filepath.Join(dir, fmt.Sprintf(TS_NAME_TEMPLATE, 0))); !isExist {
		return true
	}
	return false
}

// 进度条
func DrawProgressBar(prefix string, proportion float32, width int, suffix ...string) {
	pos := int(proportion * float32(width))
	s := fmt.Sprintf("[%s] %s%*s %6.2f%% \t%s",
		prefix, strings.Repeat("■", pos), width-pos, "", proportion*100, strings.Join(suffix, ""))
	fmt.Print("\r" + s)
}

// ============================== shell相关 ==============================
// 判断文件是否存在
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// 执行 shell
func execUnixShell(s string) {
	cmd := exec.Command("/bin/bash", "-c", s)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", out.String())
}

func execWinShell(s string) error {
	cmd := exec.Command("cmd", "/C", s)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return err
	}
	fmt.Printf("%s", out.String())
	return nil
}

// windows 合并文件
func win_merge_file(path string) {
	os.Chdir(path)
	execWinShell("copy /b *.ts merge.tmp")
	execWinShell("del /Q *.ts")
	os.Rename("merge.tmp", "merge.mp4")
}

// unix 合并文件
func unix_merge_file(path string) {
	os.Chdir(path)
	// cmd := `ls  *.ts |sort -t "\." -k 1 -n |awk '{print $0}' |xargs -n 1 -I {} bash -c "cat {} >> new.tmp"`
	cmd := `cat *.ts >> merge.tmp`
	execUnixShell(cmd)
	execUnixShell("rm -rf *.ts")
	os.Rename("merge.tmp", "merge.mp4")
}

// ============================== 加解密相关 ==============================

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func checkErr(e error) {
	if e != nil {
		logger.Panic(e)
	}
}
