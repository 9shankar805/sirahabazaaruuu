import express from 'express';
import multer from 'multer';

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Share target endpoint
router.post('/share-target', upload.array('images'), (req, res) => {
  try {
    const { title, text, url } = req.body;
    const files = req.files as Express.Multer.File[];

    console.log('Share target received:', {
      title,
      text,
      url,
      fileCount: files?.length || 0
    });

    // Process shared content
    const sharedData = {
      title: title || '',
      text: text || '',
      url: url || '',
      files: files?.map(file => ({
        name: file.originalname,
        size: file.size,
        type: file.mimetype
      })) || [],
      timestamp: new Date().toISOString()
    };

    // Redirect to share target page with data
    const params = new URLSearchParams({
      title: sharedData.title,
      text: sharedData.text,
      url: sharedData.url
    });

    res.redirect(`/share-target?${params.toString()}`);
  } catch (error) {
    console.error('Share target error:', error);
    res.redirect('/share-target?error=processing_failed');
  }
});

// Protocol handler endpoint
router.get('/protocol-handler', (req, res) => {
  try {
    const { url } = req.query;
    
    console.log('Protocol handler received:', url);

    // Redirect to protocol handler page with URL
    const params = new URLSearchParams({
      url: url as string || ''
    });

    res.redirect(`/protocol-handler?${params.toString()}`);
  } catch (error) {
    console.error('Protocol handler error:', error);
    res.redirect('/protocol-handler?error=invalid_protocol');
  }
});

// File handler endpoint
router.get('/file-handler', (req, res) => {
  try {
    const { files } = req.query;
    
    console.log('File handler received:', files);

    // Redirect to file handler page with file data
    const params = new URLSearchParams({
      files: files as string || ''
    });

    res.redirect(`/file-handler?${params.toString()}`);
  } catch (error) {
    console.error('File handler error:', error);
    res.redirect('/file-handler?error=invalid_files');
  }
});

// Widget data endpoint
router.get('/widget-data/orders', async (req, res) => {
  try {
    // Mock widget data - replace with real data from your database
    const widgetData = {
      type: "AdaptiveCard",
      version: "1.3",
      body: [
        {
          type: "TextBlock",
          text: "Quick Orders",
          weight: "bolder",
          size: "medium"
        },
        {
          type: "TextBlock",
          text: "Recent order updates",
          isSubtle: true,
          wrap: true
        },
        {
          type: "FactSet",
          facts: [
            {
              title: "Pending:",
              value: "2 orders"
            },
            {
              title: "Delivered:",
              value: "15 today"
            }
          ]
        }
      ],
      actions: [
        {
          type: "Action.OpenUrl",
          title: "View All Orders",
          url: "/orders"
        }
      ]
    };

    res.json(widgetData);
  } catch (error) {
    console.error('Widget data error:', error);
    res.status(500).json({ error: 'Failed to fetch widget data' });
  }
});

export default router;