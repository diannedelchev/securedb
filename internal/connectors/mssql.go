package connectors

import (
	"context"
	"errors"
)

// MSSQLConnector is a stub: the interface contract is in place so a real
// implementation (github.com/microsoft/go-mssqldb) can drop in without
// touching callers.
type MSSQLConnector struct{}

var errMSSQLNotImplemented = errors.New("Microsoft SQL Server support is not available yet in this MVP")

func (m *MSSQLConnector) TestConnection(_ context.Context, _ ConnectionConfig) error {
	return errMSSQLNotImplemented
}

func (m *MSSQLConnector) ExecuteQuery(_ context.Context, _ ConnectionConfig, _ QueryRequest) (QueryResult, error) {
	return QueryResult{}, errMSSQLNotImplemented
}

func (m *MSSQLConnector) ListDatabases(_ context.Context, _ ConnectionConfig) ([]DatabaseInfo, error) {
	return nil, errMSSQLNotImplemented
}

func (m *MSSQLConnector) ListSchemas(_ context.Context, _ ConnectionConfig) ([]SchemaInfo, error) {
	return nil, errMSSQLNotImplemented
}

func (m *MSSQLConnector) ListTables(_ context.Context, _ ConnectionConfig, _ string) ([]TableInfo, error) {
	return nil, errMSSQLNotImplemented
}

func (m *MSSQLConnector) ListColumns(_ context.Context, _ ConnectionConfig, _, _ string) ([]ColumnInfo, error) {
	return nil, errMSSQLNotImplemented
}
