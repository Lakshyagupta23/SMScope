const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  page.on('pageerror', err => {
    console.error('PAGE_ERROR:', err.message);
  });
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.error('CONSOLE_ERROR:', msg.text());
    }
  });
  
  await page.goto('http://localhost:5173', { waitUntil: 'networkidle2' });
  
  try {
    await page.evaluate(() => {
      const elements = Array.from(document.querySelectorAll('*'));
      const target = elements.find(el => el.textContent && el.textContent.includes('Auto-Quarantine') && el.tagName === 'BUTTON');
      if (target) {
        target.click();
      } else {
        const divTarget = elements.find(el => el.textContent && el.textContent.includes('Auto-Quarantine') && el.tagName === 'DIV');
        if(divTarget) divTarget.click();
      }
    });
    
    await new Promise(r => setTimeout(r, 2000));
  } catch (err) {
    console.error('SCRIPT_ERROR:', err);
  }
  
  await browser.close();
})();
