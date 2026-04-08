//go:build sqlite_modernc

package storage

import (
	"database/sql"
	"database/sql/driver"

	sqlite "modernc.org/sqlite"
)

func init() {
	sql.Register("sqlite3", &moderncSQLiteDriver{})
}

type moderncSQLiteDriver struct{}

func (d *moderncSQLiteDriver) Open(name string) (driver.Conn, error) {
	return (&sqlite.Driver{}).Open(name)
}
