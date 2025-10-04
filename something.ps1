    # Укажите путь к каталогу с файлами EVTX и путь к каталогу для сохранения CSV файлов
    $EVTX_catalog_files = Read-Host "Введите путь к каталогу с файлами EVTX"
    $CSV_catalog_files = Read-Host "Куда сохраняем CSV?"

    # Создайте директорию для CSV файлов, если она не существует
    if (-not (Test-Path $CSV_catalog_files)) {
        New-Item -ItemType Directory -Path $CSV_catalog_files
    }

    # Получить список всех файлов EVTX в указанной директории
    $EVTX_files = Get-ChildItem -Path $EVTX_catalog_files -Filter *.evtx

    # Цикл для обработки каждого файла EVTX и конвертации в CSV
    foreach ($file in $EVTX_files) {
        $events = Get-WinEvent -Path $file.FullName

        # Проверка на наличие событий в файле
        if ($events.Count -gt 0) {
            $CSV_name = Join-Path -Path $CSV_catalog_files -ChildPath ([System.IO.Path]::ChangeExtension($file.Name, "csv"))
            $events | Export-Csv -Path $CSV_name -NoTypeInformation
            Write-Host "Конвертирован файл: $($file.Name) в $CSV_name"
        } else {
            Write-Host "Событий нет"
        }   
    }

    # Выполняет команду 'python "C:\Users\Alex\Desktop\Новая Папка\app.py"'
    $pythonScriptPath = "C:\Users\Alex\Desktop\Potugi\app.py"
    Invoke-Expression "python `"$pythonScriptPath`" `"$CSV_catalog_files`""