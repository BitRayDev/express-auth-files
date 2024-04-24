const multer = require('multer');
const path = require("path");
const uuid = require("uuid");
const fs = require("fs");
const prisma = require("../prisma");
const express = require("express");
const storage = multer.memoryStorage();
const upload = multer({storage: storage})
const router = express.Router();

const uploadsPath = './uploads';

function getFilePath(fileName) {
    return path.join(uploadsPath, fileName);
}

function generateFileNameWithId(fileName, fileId) {
    const baseName = path.basename(fileName);
    const ext = path.extname(fileName);

    return baseName + '-' + fileId + ext;
}

function generateUniqueFileNameAndId(fileName) {
    let newFileName = null;
    let fileId = null;
    let newFilePath = null;
    do {
        fileId = uuid.v4();
        newFileName = generateFileNameWithId(fileName, fileId);
        newFilePath = path.join(uploadsPath, newFileName);
    } while (fs.existsSync(newFilePath));

    return {
        fileName: newFileName,
        fileId,
    };
}

async function saveFile(multerFile, fileName, fileId) {
    const {mimetype, size, buffer} = multerFile;

    const newFilePath = getFilePath(fileName);
    const uploadDate = new Date();

    if (fs.existsSync(newFilePath)) {
        throw new Error('File already exists');
    }

    try {
        await fs.promises.writeFile(newFilePath, buffer);
    } catch (e) {
        throw new Error(`Unexpected file system error when saving file: ${newFilePath}`)
    }

    try {
        await prisma.file.upsert({
            where: {
                id: fileId,
            },
            create: {
                id: fileId,
                name: fileName,
                mimetype,
                size,
                uploadDate,
            },
            update: {
                name: fileName,
                mimetype,
                size,
                uploadDate,
            }
        });
    } catch (e) {
        throw new Error(`Unexpected database error when saving file info: ${newFilePath}`)
    }

    return {
        file: multerFile,
        path: newFilePath,
        name: fileName,
        id: fileId,
    };
}


router.post('/upload', upload.single('file'), async (req, res) => {
    const file = req.file;
    const {originalname} = file;

    const {fileName, fileId} = generateUniqueFileNameAndId(originalname);

    try {
        await saveFile(file, fileName, fileId)
    } catch {
        return res.status(500).json({error: `Unexpected database error when saving file info: ${fileName}`})
    }

    res.status(201).json({message: 'File uploaded successfully'});
});

router.get('/list', async (req, res) => {
    const pageSize = parseInt(req.query.pageSize);
    const page = parseInt(req.query.page);

    if (isNaN(pageSize))
        return res.status(400).json({error: `Parameter 'pageSize' should be integer`});
    if (isNaN(page))
        return res.status(400).json({error: `Parameter 'page' should be integer`});


    const pageSizeWithFallback = pageSize || 10;
    const pageWithFallback = pageSize || 1;

    const offset = (pageWithFallback - 1) * pageSizeWithFallback;

    try {
        const files = await prisma.file.findMany({
            take: pageSize,
            skip: offset,
        });

        return res.json({
            data: files,
            meta: {
                pageSize: pageSizeWithFallback,
                page: pageWithFallback,
            }
        });
    } catch (e) {
        return res.status(500).json({error: `Unexpected database error when fetching files info`})
    }
});

router.get(':id', async (req, res) => {
    const id = req.params.id;

    if (!id)
        return res.status(400).json({error: `Parameter 'id' is required`});

    try {
        const fileInfo = await prisma.file.findFirst({
            where: {
                id,
            },
        });

        if (!fileInfo) {
            return res.status(404).json({error: 'File not found'});
        }

        return res.json({
            data: fileInfo
        });
    } catch (e) {
        return res.status(500).json({error: `Unexpected database error when fetching file info`})
    }
});

router.delete('/delete/:id', async (req, res) => {
    const id = req.params.id;

    if (!id)
        return res.status(400).json({error: `Parameter 'id' is required`});

    const fileInfo = await getFileInfo(id);
    if (!fileInfo) {
        return res.status(404).json({error: `File with id ${id} does not exist in the database`})
    }
    const fileName = fileInfo.name;

    const filePath = getFilePath(fileName);
    try {
        await prisma.file.delete({
            where: {
                id,
            },
        });
    } catch (e) {
        return res.status(500).json({error: `Unexpected database error when deleting file info with id ${id}`})
    }
    try {
        await fs.promises.unlink(filePath);
    } catch (e) {
        return res.status(500).json({error: `Unexpected file system error when deleting file: ${filePath}`})
    }

    res.status(204).json({message: 'File deleted successfully'});
});


router.get('/download/:id', async (req, res) => {
    const id = req.params.id;
    if (!id)
        return res.status(400).json({error: `Parameter 'id' is required`});

    const fileInfo = await getFileInfo(id);

    if (!fileInfo) {
        return res.status(404).json({error: 'File not found'});
    }

    const filePath = getFilePath(fileInfo.name);

    res.sendFile(filePath);
});

router.put('/update/:id', async (req, res) => {
    const file = req.file;
    const id = req.params.id;

    if (!id)
        return res.status(400).json({error: `Parameter 'id' is required`});

    const fileName = generateFileNameWithId(id);
    const filePath = getFilePath(fileName);

    try {
        await fs.promises.unlink(filePath);
    } catch(e) {}

    await saveFile(file, filePath, id);

    res.json({message: 'File updated successfully'});
});

module.exports = router;
