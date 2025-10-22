# Baskerville Wordpress Plugin

## Building

```commandline
zip -r9q baskerville-plugin.zip baskerville_plugin/ \
  -x "*/.DS_Store" "*/__MACOSX/*" \
     "*/.git/*" "*/.gitignore" \
     "*/.idea/*" \
     "*/node_modules/*" \
     "*.log"
```

## Installation
Upload and activate baskerville-plugin.zip in your Wordpress plugins admin page.