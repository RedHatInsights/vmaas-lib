module github.com/redhatinsights/vmaas-lib

go 1.17

require (
	github.com/ezamriy/gorpm v0.0.0-20160905202458-25f7273cbf51
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	gorm.io/driver/sqlite v1.4.3
	gorm.io/gorm v1.24.0
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.15 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)

replace github.com/ezamriy/gorpm v0.0.0-20160905202458-25f7273cbf51 => github.com/MichaelMraka/gorpm v0.0.0-20210923131407-e21b5950f175
