# SafeCheck – your own file and link scanner

- Files of ANY size: uploaded in 32 MB pieces, scanned by ClamAV on your own server, deleted right after.
  (ClamAV reads about 4 GB per file at once; bigger files are scanned in overlapping 1 GB parts.)
- Files up to 650 MB can also get the 70+ engine VirusTotal list (needs VT_API_KEY).
- Links are checked through VirusTotal (needs VT_API_KEY).

## Deploy on Render (no commands)
1. Put these files in a GitHub repository.
2. Render -> New -> Blueprint -> pick the repository.
3. Paste your VirusTotal key (or leave it empty to keep files private; links then won't work).
4. Apply. The first build takes several minutes.

The disk size in render.yaml (sizeGB) must be bigger than your biggest file. Change it before deploying.
The server needs about 2 GB of memory because the virus database is loaded into memory.
Any server that runs Docker also works: `docker build -t safecheck . && docker run -p 3000:3000 -v scans:/data -e DATA_DIR=/data safecheck`.


## Free version (default render.yaml)
Uses VirusTotal only (needs VT_API_KEY). Files up to 650 MB are uploaded and scanned; bigger files are checked by fingerprint (only works if VirusTotal already knows the file).
For your own scanner and any size, rename render-paid.yaml to render.yaml (paid server).
