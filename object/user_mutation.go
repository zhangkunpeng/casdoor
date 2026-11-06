package object

import (
	"errors"
	"fmt"
	"maps"
	"reflect"

	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/schemas"
)

var errUserMutationUnavailable = errors.New("the selected user is no longer available")

func getForUpdate(session *xorm.Session, bean interface{}, owner, name string) (bool, error) {
	engine := session.Engine()
	switch engine.Dialect().URI().DBType {
	case schemas.MYSQL, schemas.POSTGRES:
		return session.NoCache().ID(core.PK{owner, name}).ForUpdate().Get(bean)
	case schemas.SQLITE:
		// SQLite must acquire its write lock before any snapshot is read.
		table, ownerColumn, nameColumn := engine.Quote(engine.TableName(bean, true)), engine.Quote("owner"), engine.Quote("name")
		if _, err := session.Exec(fmt.Sprintf("UPDATE %s SET %s = %s WHERE %s = ? AND %s = ?", table, nameColumn, nameColumn, ownerColumn, nameColumn), owner, name); err != nil {
			return false, err
		}
		return session.NoCache().ID(core.PK{owner, name}).Get(bean)
	case schemas.MSSQL:
		query := fmt.Sprintf("SELECT * FROM %s WITH (UPDLOCK, ROWLOCK) WHERE %s = ? AND %s = ?",
			engine.Quote(engine.TableName(bean, true)), engine.Quote("owner"), engine.Quote("name"))
		return session.NoCache().SQL(query, owner, name).Get(bean)
	default:
		return false, fmt.Errorf("user mutation locking is unsupported for %s", engine.DriverName())
	}
}

func lockUserForMutation(session *xorm.Session, observed *User) (*User, error) {
	current := &User{}
	found, err := getForUpdate(session, current, observed.Owner, observed.Name)
	if err != nil {
		return nil, fmt.Errorf("lock current user: %w", err)
	}
	if !found || current.Id != observed.Id || current.IsForbidden || current.IsDeleted {
		return nil, errUserMutationUnavailable
	}
	return current, nil
}

func changedUserColumns(session *xorm.Session, current, updated *User) ([]string, error) {
	table, err := session.Engine().TableInfo(updated)
	if err != nil {
		return nil, err
	}
	before, after := reflect.ValueOf(current).Elem(), reflect.ValueOf(updated).Elem()
	var columns []string
	for _, column := range table.Columns() {
		if !reflect.DeepEqual(before.FieldByName(column.FieldName).Interface(), after.FieldByName(column.FieldName).Interface()) {
			columns = append(columns, column.Name)
		}
	}
	return columns, nil
}

func mutateUser(observed *User, apply func(*xorm.Session, *User) error) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, fmt.Errorf("begin user mutation: %w", err)
	}
	defer session.Rollback()
	current, err := lockUserForMutation(session, observed)
	if err != nil {
		return false, err
	}
	updated := *current
	updated.Properties = maps.Clone(current.Properties)
	if err := apply(session, &updated); err != nil {
		return false, err
	}
	columns, err := changedUserColumns(session, current, &updated)
	if err != nil {
		return false, fmt.Errorf("select user mutation columns: %w", err)
	}
	columns, err = prepareUserUpdate(session, &updated, append(columns, "updated_time"))
	if err != nil {
		return false, fmt.Errorf("prepare current user mutation: %w", err)
	}
	affected, err := updateUserInSession(session, current.GetId(), &updated, columns)
	if err != nil {
		return false, fmt.Errorf("persist current user mutation: %w", err)
	}
	if err := session.Commit(); err != nil {
		return false, fmt.Errorf("commit current user mutation: %w", err)
	}
	*observed = updated
	return affected != 0, nil
}
