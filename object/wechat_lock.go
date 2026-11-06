package object

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

func LockWechatUnionID(owner, unionID string) (func(), error) {
	if unionID == "" {
		return func() {}, nil
	}
	if ormer.driverName != "mysql" {
		return nil, fmt.Errorf("WeChat UnionID registration locking requires MySQL")
	}
	// A dedicated connection keeps waiting registrations out of the business pool.
	db, err := sql.Open(ormer.driverName, ormer.dataSourceName+ormer.dbName)
	if err != nil {
		return nil, fmt.Errorf("open WeChat UnionID lock connection: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("connect WeChat UnionID lock: %w", err)
	}
	closeLock := func() {
		conn.Close()
		db.Close()
	}
	hash := sha256.Sum256([]byte(ormer.dbName + ":" + owner + ":" + unionID))
	var acquired int
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 30)", hex.EncodeToString(hash[:])).Scan(&acquired); err != nil {
		closeLock()
		return nil, fmt.Errorf("acquire WeChat UnionID lock: %w", err)
	}
	if acquired != 1 {
		closeLock()
		return nil, fmt.Errorf("WeChat UnionID lock timed out")
	}
	// Closing the nonpooled MySQL connection releases its advisory lock on every return path.
	return closeLock, nil
}
