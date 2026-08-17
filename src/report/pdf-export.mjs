/**
 * PDF Export — Gera PDF do relatório HTML via Playwright headless
 */

import { chromium } from 'playwright';
import { readFileSync } from 'fs';

/**
 * Converte o relatório HTML em PDF.
 * @param {string} htmlPath - Caminho absoluto do arquivo HTML
 * @param {string} pdfPath - Caminho de saída do PDF
 */
export async function exportPdf(htmlPath, pdfPath) {
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'msedge' });
    const page = await browser.newPage();

    const htmlContent = readFileSync(htmlPath, 'utf8');
    await page.setContent(htmlContent, { waitUntil: 'networkidle' });

    await page.pdf({
      path: pdfPath,
      format: 'A4',
      margin: { top: '20mm', bottom: '20mm', left: '15mm', right: '15mm' },
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<div style="font-size:8px; text-align:center; width:100%; color:#adb5bd;">Sentinela — Relatório de Segurança</div>',
      footerTemplate: '<div style="font-size:8px; text-align:center; width:100%; color:#adb5bd;">Página <span class="pageNumber"></span> de <span class="totalPages"></span></div>',
    });
  } finally {
    if (browser) await browser.close();
  }
}
