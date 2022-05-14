package main

import (
	"fmt"
	"github.com/keybase/go-keychain"
	"os"
	"strings"
)

func userAccount() string {
	spl := strings.Split(os.Getenv("HOME"), "/")
	if len(spl) < 2 {
		panic("$HOME has not been set")
	}
	switch n := len(spl); {
	case spl[n-1] == "":
		return spl[n-2]
	default:
		return spl[n-1]
	}
}

func keychainItem() keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService("tucnak/2fa")
	item.SetAccount(userAccount())
	item.SetLabel("2fa")
	item.SetAccessGroup("2fa.group.com.github.tucnak")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	item.SetReturnData(true)
	return item
}

func queryKeychain() ([]byte, error) {
	item := keychainItem()

	results, err := keychain.QueryItem(item)
	switch err {
	case nil:
		for _, r := range results {
			return r.Data, nil
		}
		fallthrough
	case keychain.ErrorItemNotFound:
		item.SetData([]byte{})
		if err := keychain.AddItem(item); err != nil {
			return nil, fmt.Errorf("queryKeychain: no init: %w", err)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("queryKeychain: %w", err)
	}
}
