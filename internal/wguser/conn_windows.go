//+build windows

package wguser

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"unsafe"

	winio "github.com/microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Expected prefixes when dealing with named pipes.
const (
	pipePrefix = `\\.\pipe\`
	wgPrefix   = `WireGuard\`
)

// dial is the default implementation of Client.dial.
func dial(device string) (net.Conn, error) {
	// Thanks to @zx2c4 for the sample code that makes this possible:
	// https://github.com/WireGuard/wgctrl-go/issues/36#issuecomment-491912143.
	//
	// See also:
	// https://docs.microsoft.com/en-us/windows/desktop/secauthz/impersonation-tokens
	// https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-reverttoself
	//
	// All of these operations require a locked OS thread for the duration of
	// this function. Once the pipe is opened successfully, RevertToSelf
	// terminates the impersonation of a client application.
	runtime.LockOSThread()
	defer func() {
		// Terminate the token impersonation operation. Per the Microsoft
		// documentation, the process should shut down if RevertToSelf fails.
		if err := windows.RevertToSelf(); err != nil {
			panicf("wguser: failed to terminate token impersonation, panicking per Microsoft recommendation: %v", err)
		}

		runtime.UnlockOSThread()
	}()

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err := windows.LookupPrivilegeValue(
		nil,
		windows.StringToUTF16Ptr("SeDebugPrivilege"),
		&privileges.Privileges[0].Luid,
	)
	if err != nil {
		return nil, err
	}

	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return nil, err
	}

	thread, err := windows.GetCurrentThread()
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(thread)

	var threadToken windows.Token
	err = windows.OpenThreadToken(
		thread,
		windows.TOKEN_ADJUST_PRIVILEGES,
		false,
		&threadToken,
	)
	if err != nil {
		return nil, err
	}
	defer threadToken.Close()

	err = windows.AdjustTokenPrivileges(
		threadToken,
		false,
		&privileges,
		uint32(unsafe.Sizeof(privileges)),
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	processes, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(processes)

	processEntry := windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}
	var pid uint32
	for err = windows.Process32First(processes, &processEntry); err == nil; err = windows.Process32Next(processes, &processEntry) {
		if strings.ToLower(windows.UTF16ToString(processEntry.ExeFile[:])) == "winlogon.exe" {
			pid = processEntry.ProcessID
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if pid == 0 {
		return nil, errors.New("wguser: unable to find winlogon.exe process")
	}

	winlogonProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(winlogonProcess)

	var winlogonToken windows.Token
	err = windows.OpenProcessToken(
		winlogonProcess,
		windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE,
		&winlogonToken,
	)
	if err != nil {
		return nil, err
	}
	defer winlogonToken.Close()

	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(
		winlogonToken,
		0,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&duplicatedToken,
	)
	if err != nil {
		return nil, err
	}
	defer duplicatedToken.Close()

	err = windows.SetThreadToken(nil, duplicatedToken)
	if err != nil {
		return nil, err
	}

	return winio.DialPipe(device, nil)
}

// find is the default implementation of Client.find.
func find() ([]string, error) {
	return findNamedPipes(wgPrefix)
}

// findNamedPipes looks for Windows named pipes that match the specified
// search string prefix.
func findNamedPipes(search string) ([]string, error) {
	var (
		pipes []string
		data  windows.Win32finddata
	)

	// Thanks @zx2c4 for the tips on the appropriate Windows APIs here:
	// https://א.cc/dHGpnhxX/c.
	h, err := windows.FindFirstFile(
		// Append * to find all named pipes.
		windows.StringToUTF16Ptr(pipePrefix+"*"),
		&data,
	)
	if err != nil {
		return nil, err
	}

	// FindClose is used to close file search handles instead of the typical
	// CloseHandle used elsewhere, see:
	// https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-findclose.
	defer windows.FindClose(h)

	// Check the first file's name for a match, but also keep searching for
	// WireGuard named pipes until no more files can be iterated.
	for {
		name := windows.UTF16ToString(data.FileName[:])
		if strings.HasPrefix(name, search) {
			// Concatenate strings directly as filepath.Join appears to break the
			// named pipe prefix convention.
			pipes = append(pipes, pipePrefix+name)
		}

		if err := windows.FindNextFile(h, &data); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}

			return nil, err
		}
	}

	return pipes, nil
}
