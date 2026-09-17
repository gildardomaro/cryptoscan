# CryptoGuard AML Scanner

Aplicación web de **Escaneo de Billeteras y Auditoría de Riesgo AML / Forense On-Chain** para las redes más populares de la blockchain.

Inspirada en herramientas de cumplimiento como **AMLBot**, **MistTrack** y exploradores de ciberseguridad cripto.

---

## 🚀 Características Principales

1. **Soporte Multi-Blockchain:**
   - 🔴 **TRON:** Direcciones `T...` con balances de TRX y USDT (TRC-20).
   - 🔵 **Ethereum:** Direcciones `0x...` con balances de ETH y USDT/USDC (ERC-20).
   - 🟠 **Bitcoin:** Direcciones `bc1...`, `1...` o `3...` (SegWit, Legacy, Taproot).
   - 🟣 **Solana:** Direcciones Base58 con SOL y USDC SPL.
   - 🟡 **BNB Smart Chain:** Direcciones EVM con BNB y USDT BEP-20.
   - 🔷 **Polygon:** Direcciones EVM con POL.

2. **Detección Automática de Red:**
   - Identifica instantáneamente la cadena de bloques correspondiente según el formato y prefijo de la billetera ingresada.

3. **Tarjeta de Reporte de Riesgo (Idéntica a la referencia):**
   - **Snapshot AML & Balance en Tiempo Real:** Comparativa entre saldos históricos al momento del incidente y saldo on-chain actual.
   - **Nivel de Riesgo (%):** Indicador visual de 0% a 100% con categorías (*Alto*, *Medio*, *Seguro*).
   - **Gráfico de Dona Dinámico:** Implementado con Chart.js para visualizar el balance de riesgo frente a fondos limpios.
   - **Desglose de Hallazgos Forenses:** Detección de mezcladores (*Tornado Cash, Wasabi*), listas negras, estafas y patrones de *peeling chains*.
   - **Origen Estimado de Fondos:** Barras porcentuales que discriminan fondos de exchanges centralizados, P2P de riesgo, DEX y contratos sospechosos.

4. **Botones de Prueba Rápida:**
   - Incluye ejemplos preconfigurados listos para escanear con 1 clic:
     - *TRON Alto Riesgo (80%)* (Dirección de tu captura de pantalla).
     - *Ethereum Mixer (65%)*.
     - *Binance Cold Wallet (1% Seguro)*.
     - *Bitcoin Verificada (4%)*.

---

## 💻 ¿Cómo ejecutarlo localmente?

No requiere instalación de dependencias pesadas. Puedes abrirlo de dos formas:

### Opción 1: Directo en tu navegador
Haz doble clic sobre el archivo [index.html](file:///c:/Users/darku/OneDrive%20-%20imssmx/SCAN%20BLOCKCHAIN/index.html) para abrirlo directamente en Chrome, Edge o Brave.

### Opción 2: Con un servidor local (Recomendado)
Desde PowerShell o terminal:
```powershell
# Si tienes Node.js / npx:
npx serve "c:\Users\darku\OneDrive - imssmx\SCAN BLOCKCHAIN"

# O si tienes Python:
python -m http.server 8080 --directory "c:\Users\darku\OneDrive - imssmx\SCAN BLOCKCHAIN"
```
Luego abre `http://localhost:8080` en tu navegador.
