package main

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modGdi32    = syscall.NewLazyDLL("gdi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modComctl32 = syscall.NewLazyDLL("comctl32.dll")

	pRegisterClassExW     = modUser32.NewProc("RegisterClassExW")
	pCreateWindowExW      = modUser32.NewProc("CreateWindowExW")
	pDefWindowProcW       = modUser32.NewProc("DefWindowProcW")
	pShowWindow           = modUser32.NewProc("ShowWindow")
	pUpdateWindow         = modUser32.NewProc("UpdateWindow")
	pGetMessageW          = modUser32.NewProc("GetMessageW")
	pTranslateMessage     = modUser32.NewProc("TranslateMessage")
	pDispatchMessageW     = modUser32.NewProc("DispatchMessageW")
	pPostQuitMessage      = modUser32.NewProc("PostQuitMessage")
	pPostMessageW         = modUser32.NewProc("PostMessageW")
	pSendMessageW         = modUser32.NewProc("SendMessageW")
	pGetDlgItem           = modUser32.NewProc("GetDlgItem")
	pSetWindowTextW       = modUser32.NewProc("SetWindowTextW")
	pGetWindowTextW       = modUser32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW = modUser32.NewProc("GetWindowTextLengthW")
	pEnableWindow         = modUser32.NewProc("EnableWindow")
	pLoadCursorW          = modUser32.NewProc("LoadCursorW")
	pGetSysColorBrush     = modUser32.NewProc("GetSysColorBrush")
	pMessageBoxW          = modUser32.NewProc("MessageBoxW")
	pIsDlgButtonChecked   = modUser32.NewProc("IsDlgButtonChecked")
	pCheckDlgButton       = modUser32.NewProc("CheckDlgButton")
	pGetModuleHandleW     = modKernel32.NewProc("GetModuleHandleW")
	pCreateFontW          = modGdi32.NewProc("CreateFontW")
	pGetStockObject       = modGdi32.NewProc("GetStockObject")
	pInitCommonControlsEx = modComctl32.NewProc("InitCommonControlsEx")
)

const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_TABSTOP          = 0x00010000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	ES_AUTOHSCROLL      = 0x0080
	ES_AUTOVSCROLL      = 0x0040
	ES_MULTILINE        = 0x0004
	ES_READONLY         = 0x0800
	ES_NUMBER           = 0x2000
	LBS_NOTIFY          = 0x0001
	LBS_EXTENDEDSEL     = 0x0800
	LBS_HASSTRINGS      = 0x0040
	BS_PUSHBUTTON       = 0x00000000
	BS_AUTOCHECKBOX     = 0x00000003
	CBS_DROPDOWNLIST    = 0x0003
	SS_LEFT             = 0x0000
	SW_SHOW             = 5
	IDC_ARROW           = 32512
	COLOR_BTNFACE       = 15
	DEFAULT_GUI_FONT    = 17
	GB2312_CHARSET      = 134

	WM_CREATE  = 0x0001
	WM_DESTROY = 0x0002
	WM_COMMAND = 0x0111
	WM_SETFONT = 0x0030
	WM_USER    = 0x0400
	WM_APPLOG  = WM_USER + 1
	WM_APPHOST = WM_USER + 2
	WM_APPDONE = WM_USER + 4
	WM_APPIFACES = WM_USER + 6
	WM_APPBOOT   = WM_USER + 7

	BN_CLICKED    = 0
	BST_CHECKED   = 1
	BST_UNCHECKED = 0

	CB_ADDSTRING    = 0x0143
	CB_GETCURSEL    = 0x0147
	CB_SETCURSEL    = 0x014E
	CB_RESETCONTENT = 0x014B

	LB_ADDSTRING    = 0x0180
	LB_RESETCONTENT = 0x0184
	LB_SETSEL       = 0x0185
	LB_GETSELCOUNT  = 0x0190
	LB_GETSELITEMS  = 0x0191

	EM_REPLACESEL  = 0x00C2
	EM_SETSEL      = 0x00B1
	EM_SCROLLCARET = 0x00B7

	MB_OK          = 0x00000000
	MB_ICONERROR   = 0x00000010
	MB_ICONWARNING = 0x00000030
)

const (
	IDC_IFACE           = 1001
	IDC_CIDR            = 1002
	IDC_WORKERS         = 1003
	IDC_INTERVAL        = 1004
	IDC_GATEWAY         = 1005
	IDC_TARGET          = 1006
	IDC_FROM            = 1007
	IDC_TO              = 1008
	IDC_ONEWAY          = 1009
	IDC_NAME            = 1010
	IDC_HOSTLIST        = 1011
	IDC_LOG             = 1012
	IDC_STATUS          = 1013
	IDC_BTN_REFRESH     = 1101
	IDC_BTN_SCAN        = 1102
	IDC_BTN_ATTACK_SEL  = 1103
	IDC_BTN_ATTACK_RANGE = 1104
	IDC_BTN_STOP        = 1105
	IDC_BTN_SELECT_ALL  = 1106
	IDC_BTN_CLEAR_LOG   = 1107
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

type point struct{ X, Y int32 }
type msg struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}
type initCC struct {
	Size uint32
	Icc  uint32
}

type guiState struct {
	hwnd      syscall.Handle
	hFont     syscall.Handle
	mu        sync.Mutex
	ifaces    []IfaceInfo
	hosts     []Host
	logLines  []string
	scanning  bool
	attacking bool
	stopCh    chan struct{}
	// keep UTF16 pointers alive for Windows APIs
	keep []*uint16
}

var g guiState
var wndProcCallback = syscall.NewCallback(wndProc)

func u16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	// keep alive
	g.mu.Lock()
	g.keep = append(g.keep, p)
	// prevent unbounded growth
	if len(g.keep) > 5000 {
		g.keep = g.keep[len(g.keep)-2000:]
	}
	g.mu.Unlock()
	return p
}

func getCtrl(parent syscall.Handle, id int) syscall.Handle {
	h, _, _ := pGetDlgItem.Call(uintptr(parent), uintptr(id))
	return syscall.Handle(h)
}

func setText(hwnd syscall.Handle, s string) {
	if hwnd == 0 {
		return
	}
	pSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(u16(s))))
}

func getText(hwnd syscall.Handle) string {
	if hwnd == 0 {
		return ""
	}
	n, _, _ := pGetWindowTextLengthW.Call(uintptr(hwnd))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func appendLog(s string) {
	if g.hwnd == 0 {
		return
	}
	g.mu.Lock()
	g.logLines = append(g.logLines, s)
	idx := len(g.logLines) - 1
	g.mu.Unlock()
	// always async
	pPostMessageW.Call(uintptr(g.hwnd), WM_APPLOG, uintptr(idx), 0)
}

func postUI(msg uint32, wParam, lParam uintptr) {
	if g.hwnd != 0 {
		pPostMessageW.Call(uintptr(g.hwnd), uintptr(msg), wParam, lParam)
	}
}

func createChild(class, text string, style uint32, x, y, w, h int, parent syscall.Handle, id int) syscall.Handle {
	ret, _, _ := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(u16(class))),
		uintptr(unsafe.Pointer(u16(text))),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent),
		uintptr(id),
		0, 0,
	)
	if ret != 0 && g.hFont != 0 {
		pSendMessageW.Call(ret, WM_SETFONT, uintptr(g.hFont), 1)
	}
	return syscall.Handle(ret)
}

func isChecked(parent syscall.Handle, id int) bool {
	r, _, _ := pIsDlgButtonChecked.Call(uintptr(parent), uintptr(id))
	return r == BST_CHECKED
}

func setChecked(parent syscall.Handle, id int, on bool) {
	v := uintptr(BST_UNCHECKED)
	if on {
		v = BST_CHECKED
	}
	pCheckDlgButton.Call(uintptr(parent), uintptr(id), v)
}

func comboAdd(hwnd syscall.Handle, s string) {
	pSendMessageW.Call(uintptr(hwnd), CB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(s))))
}

func comboGetSel(hwnd syscall.Handle) int {
	r, _, _ := pSendMessageW.Call(uintptr(hwnd), CB_GETCURSEL, 0, 0)
	return int(int32(r))
}

func listAdd(hwnd syscall.Handle, s string) {
	pSendMessageW.Call(uintptr(hwnd), LB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(s))))
}

func listReset(hwnd syscall.Handle) {
	pSendMessageW.Call(uintptr(hwnd), LB_RESETCONTENT, 0, 0)
}

func listSelectAll(hwnd syscall.Handle, on bool) {
	v := 0
	if on {
		v = 1
	}
	pSendMessageW.Call(uintptr(hwnd), LB_SETSEL, uintptr(v), ^uintptr(0))
}

func listGetSelected(hwnd syscall.Handle) []int {
	cnt, _, _ := pSendMessageW.Call(uintptr(hwnd), LB_GETSELCOUNT, 0, 0)
	if int32(cnt) <= 0 {
		return nil
	}
	buf := make([]int32, cnt)
	pSendMessageW.Call(uintptr(hwnd), LB_GETSELITEMS, cnt, uintptr(unsafe.Pointer(&buf[0])))
	out := make([]int, len(buf))
	for i, v := range buf {
		out[i] = int(v)
	}
	return out
}

func msgBox(title, text string, flags uint32) {
	pMessageBoxW.Call(uintptr(g.hwnd), uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), uintptr(flags))
}

func boolToU(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func setBusy(hwnd syscall.Handle, scanning, attacking bool) {
	g.scanning = scanning
	g.attacking = attacking
	pEnableWindow.Call(uintptr(getCtrl(hwnd, IDC_BTN_SCAN)), boolToU(!scanning && !attacking))
	pEnableWindow.Call(uintptr(getCtrl(hwnd, IDC_BTN_ATTACK_SEL)), boolToU(!scanning && !attacking))
	pEnableWindow.Call(uintptr(getCtrl(hwnd, IDC_BTN_ATTACK_RANGE)), boolToU(!scanning && !attacking))
	pEnableWindow.Call(uintptr(getCtrl(hwnd, IDC_BTN_STOP)), boolToU(attacking))
	pEnableWindow.Call(uintptr(getCtrl(hwnd, IDC_BTN_REFRESH)), boolToU(!scanning && !attacking))
}

func loadIfacesAsync() {
	// never call from UI thread
	ifaces, err := listWindowsIfaces()
	if err != nil {
		appendLog("[-] 读取网卡失败: " + err.Error())
		postUI(WM_APPIFACES, 1, 0)
		return
	}
	// 不调用 PacketGetAdapterNames，避免卡住
	ifaces = fillPcapNames(ifaces)
	g.mu.Lock()
	g.ifaces = ifaces
	g.mu.Unlock()
	appendLog(fmt.Sprintf("[+] 网卡加载完成: %d 张", len(ifaces)))
	postUI(WM_APPIFACES, 0, 0)
}

func applyIfacesUI(hwnd syscall.Handle) {
	hCombo := getCtrl(hwnd, IDC_IFACE)
	pSendMessageW.Call(uintptr(hCombo), CB_RESETCONTENT, 0, 0)
	g.mu.Lock()
	ifaces := append([]IfaceInfo(nil), g.ifaces...)
	g.mu.Unlock()
	best := 0
	for i, it := range ifaces {
		gw := "-"
		if it.Gateway != nil {
			gw = it.Gateway.String()
		}
		label := fmt.Sprintf("%s | %s | 网关 %s", it.Description, it.IP, gw)
		comboAdd(hCombo, label)
		if it.Gateway != nil && !it.Gateway.IsUnspecified() && len(it.IP) > 0 && it.IP[0] == 192 {
			best = i
		}
	}
	if len(ifaces) == 0 {
		setText(getCtrl(hwnd, IDC_STATUS), "状态: 未发现可用网卡")
		return
	}
	pSendMessageW.Call(uintptr(hCombo), CB_SETCURSEL, uintptr(best), 0)
	if ifaces[best].Gateway != nil {
		setText(getCtrl(hwnd, IDC_GATEWAY), ifaces[best].Gateway.String())
	}
	if ip := ifaces[best].IP.To4(); ip != nil {
		setText(getCtrl(hwnd, IDC_CIDR), fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2]))
	}
	setText(getCtrl(hwnd, IDC_STATUS), fmt.Sprintf("状态: 就绪 | 网卡 %d 张", len(ifaces)))
}

func refreshIfacesUI(hwnd syscall.Handle) {
	setText(getCtrl(hwnd, IDC_STATUS), "状态: 正在加载网卡...")
	appendLog("[*] 后台加载网卡列表...")
	go loadIfacesAsync()
}

func selectedIface(hwnd syscall.Handle) (IfaceInfo, error) {
	idx := comboGetSel(getCtrl(hwnd, IDC_IFACE))
	g.mu.Lock()
	defer g.mu.Unlock()
	if idx < 0 || idx >= len(g.ifaces) {
		return IfaceInfo{}, fmt.Errorf("请选择网卡（若刚启动请等待网卡加载完成）")
	}
	return g.ifaces[idx], nil
}

func fillHostList(hwnd syscall.Handle) {
	hList := getCtrl(hwnd, IDC_HOSTLIST)
	listReset(hList)
	g.mu.Lock()
	hosts := append([]Host(nil), g.hosts...)
	g.mu.Unlock()
	for _, h := range hosts {
		name := h.Name
		if name == "" {
			name = "-"
		}
		line := fmt.Sprintf("%-16s  %-18s  %-20s  %s", h.IP, h.MAC, name, h.Note)
		listAdd(hList, line)
	}
	setText(getCtrl(hwnd, IDC_STATUS), fmt.Sprintf("状态: 就绪 | 设备 %d 台", len(hosts)))
}

func doScan(hwnd syscall.Handle) {
	if g.scanning || g.attacking {
		return
	}
	iface, err := selectedIface(hwnd)
	if err != nil {
		msgBox("提示", err.Error(), MB_ICONWARNING)
		return
	}
	cidr := strings.TrimSpace(getText(getCtrl(hwnd, IDC_CIDR)))
	workers, _ := strconv.Atoi(strings.TrimSpace(getText(getCtrl(hwnd, IDC_WORKERS))))
	if workers <= 0 {
		workers = 64
	}
	if workers > 128 {
		workers = 128
	}
	resolveName := isChecked(hwnd, IDC_NAME)
	if resolveName && workers > 32 {
		workers = 32
	}
	setBusy(hwnd, true, false)
	setText(getCtrl(hwnd, IDC_STATUS), "状态: 正在扫描（后台进行）...")
	appendLog(fmt.Sprintf("[*] 开始扫描 %s workers=%d 解析名称=%v", cidr, workers, resolveName))
	go func() {
		doneHB := make(chan struct{})
		go func() {
			tk := time.NewTicker(2 * time.Second)
			defer tk.Stop()
			n := 0
			for {
				select {
				case <-doneHB:
					return
				case <-tk.C:
					n++
					appendLog(fmt.Sprintf("[*] 扫描进行中... %ds", n*2))
				}
			}
		}()
		hosts, err := scanLAN(iface, cidr, workers, 500*time.Millisecond, resolveName, 300*time.Millisecond)
		close(doneHB)
		if err != nil {
			appendLog("[-] 扫描失败: " + err.Error())
			postUI(WM_APPDONE, 1, 0)
			return
		}
		for i := range hosts {
			if iface.Gateway != nil && hosts[i].IP.Equal(iface.Gateway) {
				hosts[i].Note = "网关"
			}
			if hosts[i].IP.Equal(iface.IP) {
				hosts[i].Note = "本机"
			}
		}
		g.mu.Lock()
		g.hosts = hosts
		g.mu.Unlock()
		appendLog(fmt.Sprintf("[+] 扫描完成，发现 %d 台设备", len(hosts)))
		postUI(WM_APPHOST, 0, 0)
		postUI(WM_APPDONE, 0, 0)
	}()
}

func startAttack(hwnd syscall.Handle, targets []net.IP, tag string) {
	if len(targets) == 0 {
		msgBox("提示", "没有可攻击的目标", MB_ICONWARNING)
		return
	}
	iface, err := selectedIface(hwnd)
	if err != nil {
		msgBox("提示", err.Error(), MB_ICONWARNING)
		return
	}
	gwText := strings.TrimSpace(getText(getCtrl(hwnd, IDC_GATEWAY)))
	var gip net.IP
	if gwText != "" {
		gip = net.ParseIP(gwText)
		if gip == nil || gip.To4() == nil {
			msgBox("提示", "网关 IP 无效", MB_ICONWARNING)
			return
		}
	} else if iface.Gateway != nil {
		gip = iface.Gateway
	} else {
		msgBox("提示", "未知网关，请填写网关 IP", MB_ICONWARNING)
		return
	}
	intervalMs, _ := strconv.Atoi(strings.TrimSpace(getText(getCtrl(hwnd, IDC_INTERVAL))))
	if intervalMs < 100 {
		intervalMs = 1000
	}
	workers, _ := strconv.Atoi(strings.TrimSpace(getText(getCtrl(hwnd, IDC_WORKERS))))
	if workers <= 0 {
		workers = 32
	}
	oneWay := isChecked(hwnd, IDC_ONEWAY)
	resolveName := isChecked(hwnd, IDC_NAME)
	if g.stopCh != nil {
		select {
		case <-g.stopCh:
		default:
			close(g.stopCh)
		}
	}
	g.stopCh = make(chan struct{})
	setBusy(hwnd, false, true)
	setText(getCtrl(hwnd, IDC_STATUS), fmt.Sprintf("状态: 攻击中 | 目标 %d | %s", len(targets), tag))
	appendLog(fmt.Sprintf("[*] 启动多线程攻击: %d 个目标 (%s)", len(targets), tag))
	for _, t := range targets {
		appendLog("    目标: " + t.String())
	}
	stop := g.stopCh
	go func() {
		err := poisonLoopConcurrent(iface, targets, gip.To4(), time.Duration(intervalMs)*time.Millisecond, oneWay, nil, resolveName, workers, stop, appendLog)
		if err != nil {
			appendLog("[-] 攻击结束错误: " + err.Error())
		} else {
			appendLog("[+] 攻击已停止")
		}
		postUI(WM_APPDONE, 2, 0)
	}()
}

func attackSelected(hwnd syscall.Handle) {
	idxs := listGetSelected(getCtrl(hwnd, IDC_HOSTLIST))
	g.mu.Lock()
	hosts := append([]Host(nil), g.hosts...)
	g.mu.Unlock()
	var targets []net.IP
	for _, i := range idxs {
		if i >= 0 && i < len(hosts) {
			targets = append(targets, hosts[i].IP.To4())
		}
	}
	if len(targets) == 0 {
		spec := strings.TrimSpace(getText(getCtrl(hwnd, IDC_TARGET)))
		if spec == "" {
			msgBox("提示", "请先在列表中勾选设备，或填写目标 IP/段", MB_ICONWARNING)
			return
		}
		ips, err := parseIPList(spec)
		if err != nil {
			msgBox("错误", err.Error(), MB_ICONERROR)
			return
		}
		targets = ips
	}
	startAttack(hwnd, targets, "选中/指定目标")
}

func attackRange(hwnd syscall.Handle) {
	from := strings.TrimSpace(getText(getCtrl(hwnd, IDC_FROM)))
	to := strings.TrimSpace(getText(getCtrl(hwnd, IDC_TO)))
	spec := strings.TrimSpace(getText(getCtrl(hwnd, IDC_TARGET)))
	ips, err := collectTargets(spec, from, to)
	if err != nil {
		msgBox("错误", err.Error(), MB_ICONERROR)
		return
	}
	startAttack(hwnd, ips, "IP段批量")
}

func stopAttack(hwnd syscall.Handle) {
	if g.stopCh != nil {
		select {
		case <-g.stopCh:
		default:
			close(g.stopCh)
		}
	}
	appendLog("[*] 正在请求停止攻击...")
	setText(getCtrl(hwnd, IDC_STATUS), "状态: 正在停止...")
}

func onCreate(hwnd syscall.Handle) {
	g.hwnd = hwnd

	// font
	hf, _, _ := pCreateFontW.Call(
		uintptr(18), 0, 0, 0, 400, 0, 0, 0,
		GB2312_CHARSET, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(u16("Microsoft YaHei UI"))),
	)
	if hf == 0 {
		hf, _, _ = pGetStockObject.Call(DEFAULT_GUI_FONT)
	}
	g.hFont = syscall.Handle(hf)

	y := 10
	createChild("STATIC", "网卡:", WS_CHILD|WS_VISIBLE|SS_LEFT, 10, y+4, 50, 22, hwnd, 2001)
	createChild("COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL, 60, y, 520, 200, hwnd, IDC_IFACE)
	createChild("BUTTON", "刷新网卡", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 590, y, 90, 28, hwnd, IDC_BTN_REFRESH)
	y += 36
	createChild("STATIC", "扫描网段:", WS_CHILD|WS_VISIBLE, 10, y+4, 70, 22, hwnd, 2002)
	createChild("EDIT", "192.168.31.0/24", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 80, y, 160, 26, hwnd, IDC_CIDR)
	createChild("STATIC", "线程数:", WS_CHILD|WS_VISIBLE, 250, y+4, 55, 22, hwnd, 2003)
	createChild("EDIT", "64", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_NUMBER|ES_AUTOHSCROLL, 305, y, 50, 26, hwnd, IDC_WORKERS)
	createChild("STATIC", "间隔ms:", WS_CHILD|WS_VISIBLE, 365, y+4, 55, 22, hwnd, 2004)
	createChild("EDIT", "1000", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_NUMBER|ES_AUTOHSCROLL, 420, y, 60, 26, hwnd, IDC_INTERVAL)
	createChild("STATIC", "网关:", WS_CHILD|WS_VISIBLE, 490, y+4, 40, 22, hwnd, 2005)
	createChild("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 530, y, 150, 26, hwnd, IDC_GATEWAY)
	y += 36
	createChild("STATIC", "目标IP/段:", WS_CHILD|WS_VISIBLE, 10, y+4, 75, 22, hwnd, 2006)
	createChild("EDIT", "192.168.31.105-192.168.31.110", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 85, y, 260, 26, hwnd, IDC_TARGET)
	createChild("STATIC", "从:", WS_CHILD|WS_VISIBLE, 355, y+4, 25, 22, hwnd, 2007)
	createChild("EDIT", "192.168.31.105", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 380, y, 120, 26, hwnd, IDC_FROM)
	createChild("STATIC", "到:", WS_CHILD|WS_VISIBLE, 510, y+4, 25, 22, hwnd, 2008)
	createChild("EDIT", "192.168.31.110", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 535, y, 145, 26, hwnd, IDC_TO)
	y += 36
	createChild("BUTTON", "解析设备名称", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 10, y, 120, 24, hwnd, IDC_NAME)
	createChild("BUTTON", "仅单向污染", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 140, y, 110, 24, hwnd, IDC_ONEWAY)
	setChecked(hwnd, IDC_NAME, true)
	createChild("BUTTON", "扫描局域网", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 270, y-2, 100, 28, hwnd, IDC_BTN_SCAN)
	createChild("BUTTON", "全选列表", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 380, y-2, 90, 28, hwnd, IDC_BTN_SELECT_ALL)
	createChild("BUTTON", "攻击选中", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 480, y-2, 90, 28, hwnd, IDC_BTN_ATTACK_SEL)
	createChild("BUTTON", "攻击IP段", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 580, y-2, 90, 28, hwnd, IDC_BTN_ATTACK_RANGE)
	y += 34
	createChild("BUTTON", "停止并恢复", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 10, y, 110, 28, hwnd, IDC_BTN_STOP)
	createChild("BUTTON", "清空日志", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 130, y, 90, 28, hwnd, IDC_BTN_CLEAR_LOG)
	createChild("STATIC", "状态: 界面已就绪", WS_CHILD|WS_VISIBLE, 240, y+5, 440, 22, hwnd, IDC_STATUS)
	y += 36
	createChild("STATIC", "设备列表（可多选）:", WS_CHILD|WS_VISIBLE, 10, y, 200, 20, hwnd, 2009)
	y += 22
	createChild("LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY|LBS_EXTENDEDSEL|LBS_HASSTRINGS, 10, y, 680, 180, hwnd, IDC_HOSTLIST)
	y += 190
	createChild("STATIC", "运行日志:", WS_CHILD|WS_VISIBLE, 10, y, 100, 20, hwnd, 2010)
	y += 22
	createChild("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_AUTOHSCROLL|ES_READONLY, 10, y, 680, 170, hwnd, IDC_LOG)

	setBusy(hwnd, false, false)
	pEnableWindow.Call(uintptr(getCtrl(hwnd, IDC_BTN_STOP)), 0)
	// 不在这里做任何网络/Npcap 调用
	setText(getCtrl(hwnd, IDC_STATUS), "状态: 界面已就绪，正在后台加载网卡...")
	postUI(WM_APPBOOT, 0, 0)
}

func wndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		onCreate(hwnd)
		return 0
	case WM_COMMAND:
		id := int(wParam & 0xFFFF)
		notify := int((wParam >> 16) & 0xFFFF)
		if notify == BN_CLICKED || notify == 0 {
			switch id {
			case IDC_BTN_REFRESH:
				refreshIfacesUI(hwnd)
			case IDC_BTN_SCAN:
				doScan(hwnd)
			case IDC_BTN_SELECT_ALL:
				listSelectAll(getCtrl(hwnd, IDC_HOSTLIST), true)
			case IDC_BTN_ATTACK_SEL:
				attackSelected(hwnd)
			case IDC_BTN_ATTACK_RANGE:
				attackRange(hwnd)
			case IDC_BTN_STOP:
				stopAttack(hwnd)
			case IDC_BTN_CLEAR_LOG:
				setText(getCtrl(hwnd, IDC_LOG), "")
			}
		}
		return 0
	case WM_APPLOG:
		idx := int(wParam)
		g.mu.Lock()
		var line string
		if idx >= 0 && idx < len(g.logLines) {
			line = g.logLines[idx]
		}
		g.mu.Unlock()
		if line != "" {
			hLog := getCtrl(hwnd, IDC_LOG)
			pSendMessageW.Call(uintptr(hLog), EM_SETSEL, ^uintptr(0), ^uintptr(0))
			text := line + "\r\n"
			pSendMessageW.Call(uintptr(hLog), EM_REPLACESEL, 0, uintptr(unsafe.Pointer(u16(text))))
			pSendMessageW.Call(uintptr(hLog), EM_SCROLLCARET, 0, 0)
		}
		return 0
	case WM_APPHOST:
		fillHostList(hwnd)
		return 0
	case WM_APPBOOT:
		appendLog("winarp GUI - CTF 局域网扫描 / 多线程 ARP 污染")
		appendLog("提示: 需要管理员权限 + Npcap；仅用于授权 CTF 沙箱")
		go loadIfacesAsync()
		return 0
	case WM_APPIFACES:
		if wParam == 0 {
			applyIfacesUI(hwnd)
		} else {
			setText(getCtrl(hwnd, IDC_STATUS), "状态: 网卡加载失败")
		}
		return 0
	case WM_APPDONE:
		setBusy(hwnd, false, false)
		if wParam == 2 {
			setText(getCtrl(hwnd, IDC_STATUS), "状态: 已停止")
		} else if wParam == 1 {
			setText(getCtrl(hwnd, IDC_STATUS), "状态: 扫描失败")
		}
		return 0
	case WM_DESTROY:
		if g.stopCh != nil {
			select {
			case <-g.stopCh:
			default:
				close(g.stopCh)
			}
		}
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func runGUI() error {
	// 关键：GUI 消息循环必须固定在同一 OS 线程
	runtime.LockOSThread()

	// common controls best-effort
	icc := initCC{Size: 8, Icc: 0x00004000}
	pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	hInst, _, _ := pGetModuleHandleW.Call(0)
	className := u16("WinArpMainWndV2")

	var wc wndClassEx
	wc.Size = uint32(unsafe.Sizeof(wc))
	wc.WndProc = wndProcCallback
	wc.Instance = syscall.Handle(hInst)
	bg, _, _ := pGetSysColorBrush.Call(COLOR_BTNFACE)
	wc.Background = syscall.Handle(bg)
	cur, _, _ := pLoadCursorW.Call(0, uintptr(IDC_ARROW))
	wc.Cursor = syscall.Handle(cur)
	wc.ClassName = className

	atom, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return fmt.Errorf("RegisterClassExW failed: %v", err)
	}

	hwnd, _, err := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(u16("winarp - 局域网扫描与ARP污染 (CTF)"))),
		uintptr(WS_OVERLAPPEDWINDOW|WS_VISIBLE),
		uintptr(120), uintptr(80), uintptr(720), uintptr(640),
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %v", err)
	}
	g.hwnd = syscall.Handle(hwnd)
	pShowWindow.Call(hwnd, SW_SHOW)
	pUpdateWindow.Call(hwnd)

	var m msg
	for {
		ret, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}
