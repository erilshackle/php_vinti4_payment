<?php

/**
 * Classe Vinti4Payment
 *
 * Integração direta com o gateway Vinti4/SISP para processamento de pagamentos online.
 * Implementa geração de fingerprint, criação de formulários e validação/processamento de respostas.
 */
class Vinti4Payment
{
    /** @var string Identificador POS */
    private string $posID;

    /** @var string Código de autorização POS (confidencial) */
    private string $posAutCode;

    /** @var string Endpoint fixo do gateway Vinti4 */
    private string $endpoint = 'https://mc.vinti4net.cv/BizMPIOnUs/CardPayment';

    /** @var array Resultado da última validação de resposta */
    private array $result = [];

    /** @var string Código da moeda (132 = Escudo Cabo-Verdiano) */
    public string $currency = '132';

    /** @var string Idioma das mensagens */
    public string $language = 'pt';

    /** @var string Versão do fingerprint */
    private const FINGERPRINT_VERSION = '1';

    /** @var array Códigos de sucesso da Vinti4 */
    private const SUCCESS_TYPES = ['8', '10', 'P', 'M'];

    /**
     * Construtor.
     *
     * @param string $posID Identificador POS
     * @param string $posAutCode Código de autorização POS
     */
    public function __construct(string $posID, string $posAutCode)
    {
        $this->posID = $posID;
        $this->posAutCode = $posAutCode;
    }

    /**
     * Cria um pagamento, retornando os dados prontos para envio.
     *
     * @param string $amount Valor da transação (ex: "1000.00")
     * @param string $responseUrl URL para resposta do pagamento
     * @param array  $extras Campos adicionais (entityCode, referenceNumber, transactionCode, etc.)
     *
     * @return array Campos completos a serem enviados ao gateway
     */
    public function createPayment(string $amount, string $responseUrl, array $extras = []): array
    {
        $merchantRef = 'R' . date('YmdHis');
        $merchantSession = 'S' . date('YmdHis');
        $timestamp = date('Y-m-d H:i:s');

        $fields = array_merge([
            'transactionCode'     => $extras['transactionCode'] ?? '1', // 1 = Compra padrão
            'posID'               => $this->posID,
            'merchantRef'         => $merchantRef,
            'merchantSession'     => $merchantSession,
            'amount'              => $amount,
            'currency'            => $this->currency,
            'is3DSec'             => '1',
            'urlMerchantResponse' => $responseUrl,
            'languageMessages'    => $this->language,
            'timeStamp'           => $timestamp,
            'fingerprintversion'  => self::FINGERPRINT_VERSION,
            'entityCode'          => $extras['entityCode'] ?? '',
            'referenceNumber'     => $extras['referenceNumber'] ?? '',
        ], $extras);

        $fields['fingerprint'] = $this->generateRequestFingerprint($fields);

        $fields['postUrl'] = $this->endpoint . '?' . http_build_query([
            'FingerPrint'        => $fields['fingerprint'],
            'TimeStamp'          => $fields['timeStamp'],
            'FingerPrintVersion' => $fields['fingerprintversion'],
        ]);

        return $fields;
    }

    /**
     * Renderiza o formulário HTML de pagamento com auto-submit.
     *
     * @param array $fields Campos gerados por createPayment()
     * @return string HTML do formulário completo
     */
    public function renderPaymentForm(array $fields): string
    {
        $inputs = '';
        foreach ($fields as $k => $v) {
            if ($k === 'postUrl') continue;
            $inputs .= sprintf(
                "<input type='hidden' name='%s' value='%s'>\n",
                htmlspecialchars($k, ENT_QUOTES),
                htmlspecialchars((string)$v, ENT_QUOTES)
            );
        }

        $action = htmlspecialchars($fields['postUrl'], ENT_QUOTES);

        return <<<HTML
        <form id="vinti4Form" action="{$action}" method="post">
            {$inputs}
        </form>
        <script>document.getElementById('vinti4Form').submit();</script>
        HTML;
    }

    /**
     * Processa a resposta recebida do gateway Vinti4.
     *
     * Executa a validação do FingerPrint e verifica o status da transação.
     * Retorna um array padronizado contendo as informações do resultado.
     *
     * @param array $response Dados recebidos via POST do gateway
     * @return array{valid:bool, success:bool, message:string,data:array} [valid, success, message, data]
     */
    public function processResponse(array $response): array
    {
        $this->result = [
            'valid'   => false,
            'success' => false,
            'message' => 'Resposta inválida ou incompleta.',
            'data'    => $response
        ];

        // Tipos de mensagem considerados sucesso
        $successTypes = ['8', '10', 'P', 'M'];

        // Verifica tipo de mensagem
        $messageType = $response['messageType'] ?? null;
        if (!$messageType) {
            $this->result['message'] = 'Campo "messageType" ausente.';
            return $this->result;
        }

        // Verifica se é transação bem-sucedida
        if (!in_array($messageType, $successTypes, true)) {
            $desc = $response['merchantRespErrorDescription'] ?? 'Transação não autorizada.';
            $detail = $response['merchantRespErrorDetail'] ?? '';
            $this->result['message'] = trim("$desc $detail");
            return $this->result;
        }

        // Calcula o fingerprint esperado
        $expected = $this->generateResponseFingerprint($response);
        $received = $response['resultFingerPrint'] ?? '';

        // Valida FingerPrint
        if ($received !== $expected) {
            $this->result['message'] = 'Fingerprint inválido (falha de verificação de integridade).';
            return $this->result;
        }

        // Tudo OK
        $this->result = [
            'valid'   => true,
            'success' => true,
            'message' => 'Pagamento validado com sucesso.',
            'data'    => $response
        ];

        return $this->result;
    }


    /**
     * Retorna o resultado da última validação.
     *
     * @return array Estrutura contendo valid, success, message e data
     */
    public function result(): array
    {
        return $this->result;
    }

    // ===========================================================
    // Métodos privados
    // ===========================================================

    /** Gera o fingerprint de envio. */
    private function generateRequestFingerprint(array $f): string
    {
        $entity = (int)($f['entityCode'] ?? 0);
        $reference = (int)($f['referenceNumber'] ?? 0);

        $toHash = base64_encode(hash('sha512', $this->posAutCode, true))
            . $f['timeStamp']
            . (int)((float)$f['amount'] * 1000)
            . $f['merchantRef']
            . $f['merchantSession']
            . $f['posID']
            . $f['currency']
            . $f['transactionCode']
            . $entity
            . $reference;

        return base64_encode(hash('sha512', $toHash, true));
    }

    /** Gera o fingerprint de resposta (callback). */
    private function generateResponseFingerprint(array $f): string
    {
        $entity = (int)($f['merchantRespEntityCode'] ?? 0);
        $reference = (int)($f['merchantRespReferenceNumber'] ?? 0);
        $amount = (int)((float)($f['merchantRespPurchaseAmount'] ?? 0) * 1000);

        $concat = base64_encode(hash('sha512', $this->posAutCode, true))
            . ($f['messageType'] ?? '')
            . ($f['merchantRespCP'] ?? '')
            . ($f['merchantRespTid'] ?? '')
            . ($f['merchantRespMerchantRef'] ?? '')
            . ($f['merchantRespMerchantSession'] ?? '')
            . $amount
            . ($f['merchantRespMessageID'] ?? '')
            . ($f['merchantRespPan'] ?? '')
            . ($f['merchantResp'] ?? '')
            . ($f['merchantRespTimeStamp'] ?? '')
            . $reference
            . $entity
            . ($f['merchantRespClientReceipt'] ?? '')
            . trim($f['merchantRespAdditionalErrorMessage'] ?? '')
            . ($f['merchantRespReloadCode'] ?? '');

        return base64_encode(hash('sha512', $concat, true));
    }
}
