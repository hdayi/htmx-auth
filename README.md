# BASLIK

1. go mod init
2. air config
3. gitignore
4. Makefile
5. tailwind setup

   - tailwind.config.js
   - ./tailwind/input.css
   - mkdir -p static/css

6. templ

   - go get github.com/a-h/templ
   - index.templ

   ```html
   <link href="/static/css/style.css" rel="stylesheet" />
   <script src="https://cdn.tailwindcss.com"></script>
   <script
     src="https://unpkg.com/htmx.org@1.9.12"
     integrity="sha384-ujb1lZYygJmzgSwoxRggbCHcjc0rB2XoQrxeTUQyRjrOnlCoYta87iKBWq3EsdM2"
     crossorigin="anonymous"
   ></script>
   <link
     rel="stylesheet"
     href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200"
   />
   ```

7. main.go

````go
    func main() {
    e := echo.New()
    e.Static("/static", "static")

    e.GET("/", func(c echo.Context) error {
      return templates.Index().Render(context.Background(), c.Response().Writer)
      // return c.String(http.StatusOK, "Hello, World!")
    })

    e.Logger.Fatal(e.Start(":8080"))
    }
    ```
````
