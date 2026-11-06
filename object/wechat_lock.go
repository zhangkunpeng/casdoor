package object

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

func (a *Ormer) openWechatLockPool() error {
	if a.driverName != "mysql" {
		return nil
	}
	db, err := sql.Open(a.driverName, a.dataSourceName+a.dbName)
	if err != nil {
		return fmt.Errorf("open WeChat registration lock pool: %w", err)
	}
	// A holder and a waiter may occupy both connections; business queries use a separate pool.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	a.wechatLockDB = db
	return nil
}

// LockWechatOrganization serializes all WeChat registration paths across processes on the shared MySQL database.
func LockWechatOrganization(owner string) (func(), error) {
	if ormer.driverName != "mysql" {
		return nil, fmt.Errorf("WeChat registration locking requires MySQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	conn, err := ormer.wechatLockDB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(ormer.dbName + ":wechat:" + owner))
	key := hex.EncodeToString(hash[:])
	var acquired int
	if err = conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 30)", key).Scan(&acquired); err != nil || acquired != 1 {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
		if err != nil {
			return nil, fmt.Errorf("acquire WeChat registration lock: %w", err)
		}
		return nil, fmt.Errorf("WeChat registration lock timed out")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer releaseCancel()
			var released int
			if err := conn.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", key).Scan(&released); err != nil || released != 1 {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
			_ = conn.Close()
		})
	}, nil
}
