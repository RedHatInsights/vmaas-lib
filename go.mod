module github.com/redhatinsights/vmaas-lib

go 1.17

require (
	github.com/ezamriy/gorpm v0.0.0-20160905202458-25f7273cbf51
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.0
	gorm.io/driver/sqlite v1.4.3
	gorm.io/gorm v1.24.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.16 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ezamriy/gorpm v0.0.0-20160905202458-25f7273cbf51 => github.com/psegedy/gorpm v0.0.0-20221128152921-427315f73216
