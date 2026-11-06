package object

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xorm-io/xorm"
)

func TestUserMutationSQLiteLocksBeforeReading(t *testing.T) {
	engine, err := xorm.NewEngine("sqlite", filepath.Join(t.TempDir(), "mutation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err := engine.Sync2(&Organization{}, &Token{}, &User{}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		bean    interface{}
		newBean func() interface{}
	}{
		{"organization", &Organization{Owner: "owner", Name: "name", DisplayName: "original"}, func() interface{} { return &Organization{} }},
		{"token", &Token{Owner: "owner", Name: "name", AccessTokenHash: "original"}, func() interface{} { return &Token{} }},
		{"user", &User{Owner: "owner", Name: "name", Id: "original", Phone: "12345678"}, func() interface{} { return &User{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := engine.Insert(test.bean); err != nil {
				t.Fatal(err)
			}
			before := test.newBean()
			if _, err := engine.Get(before); err != nil {
				t.Fatal(err)
			}
			locked := engine.NewSession()
			defer locked.Close()
			if err := locked.Begin(); err != nil {
				t.Fatal(err)
			}
			defer locked.Rollback()
			read := test.newBean()
			if found, err := getForUpdate(locked, read, "owner", "name"); err != nil || !found {
				t.Fatalf("lock current row: %t / %v", found, err)
			}
			if !reflect.DeepEqual(before, read) {
				t.Fatal("lock acquisition changed row fields")
			}
			competing := engine.NewSession()
			defer competing.Close()
			if err := competing.Begin(); err != nil {
				t.Fatal(err)
			}
			if _, err := getForUpdate(competing, test.newBean(), "owner", "name"); err == nil {
				t.Fatal("a second transaction acquired the SQLite write lock")
			}
			if err := competing.Rollback(); err != nil {
				t.Fatal(err)
			}
			if err := locked.Commit(); err != nil {
				t.Fatal(err)
			}
			after := test.newBean()
			if _, err := engine.Get(after); err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("locking altered persisted row: %v", err)
			}
		})
	}
}
