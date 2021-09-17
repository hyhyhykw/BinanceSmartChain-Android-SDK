package com.centerprime.binance_smart_chain_sdk;

import android.content.Context;

import com.centerprime.binance_smart_chain_sdk.util.BalanceUtils;
import com.centerprime.binance_smart_chain_sdk.util.CenterPrimeUtils;
import com.centerprime.binance_smart_chain_sdk.util.Const;
import com.centerprime.binance_smart_chain_sdk.util.Erc20TokenWrapper;
import com.centerprime.binance_smart_chain_sdk.util.Token;
import com.centerprime.binance_smart_chain_sdk.util.Wallet;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.HDUtils;
import org.bitcoinj.crypto.MnemonicCode;
import org.spongycastle.util.encoders.Hex;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.response.NoOpProcessor;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

import io.reactivex.Single;

/**
 * Created by CenterPrime on 2020/09/19.
 */
public class BinanceManager {

    private static final BinanceManager ourInstance = new BinanceManager();

    /**
     * Web3j Client
     */
    private Web3j web3j;

    /**
     * Infura node url
     */
    private String mainnetInfuraUrl = "";

    public static BinanceManager getInstance() {
        return ourInstance;
    }

    public BinanceManager() {
//        init("https://data-seed-prebsc-1-s1.binance.org:8545");
    }

    /**
     * Initialize EthManager
     *
     * @param mainnetInfuraUrl : Infura Url
     */
    public void init(String mainnetInfuraUrl) {
        this.mainnetInfuraUrl = mainnetInfuraUrl;
        web3j = Web3j.build(new HttpService(mainnetInfuraUrl, false));
    }

    /**
     * Get Current Gas Price
     */
    public BigInteger getGasPrice() {
        try {
            EthGasPrice price = web3j.ethGasPrice()
                    .send();
            return price.getGasPrice();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new BigInteger(Const.DEFAULT_GAS_PRICE);
    }


    /**
     * Create Wallet by password
     */
    public Single<Wallet> createWallet(String password, Context context) {
        return Single.fromCallable(() -> {
            try {

                String walletAddress = CenterPrimeUtils.generateNewWalletFile(password, new File(context.getFilesDir(), ""), false);
                String walletPath = context.getFilesDir() + "/" + walletAddress.toLowerCase();
                File keystoreFile = new File(walletPath);
                String keystore = read_file(context, keystoreFile.getName());
                return new Wallet(walletAddress, keystore);
            } catch (CipherException | IOException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
                e.printStackTrace();
            }
            return null;
        });
    }

    /**
     * Export Keystore by wallet address
     */
    public Single<String> exportKeyStore(String walletAddress, Context context) {
        return Single.fromCallable(() -> {
            String wallet = walletAddress;
            if (wallet.startsWith("0x")) {
                wallet = wallet.substring(2);
            }
            String walletPath = context.getFilesDir() + "/" + wallet.toLowerCase();
            File keystoreFile = new File(walletPath);
            if (keystoreFile.exists()) {

                return read_file(context, keystoreFile.getName());
            } else {
                throw new Exception("Keystore is NULL");
            }
        });
    }

    /**
     * Get Keystore by wallet address
     */
    public Single<String> getKeyStore(String walletAddress, Context context) {
        return Single.fromCallable(() -> {
            String wallet = walletAddress;
            if (wallet.startsWith("0x")) {
                wallet = wallet.substring(2);
            }
            String walletPath = context.getFilesDir() + "/" + wallet.toLowerCase();
            File keystoreFile = new File(walletPath);
            if (keystoreFile.exists()) {
                return read_file(context, keystoreFile.getName());
            } else {
                throw new Exception("Keystore is NULL");
            }
        });
    }

    /**
     * Import Wallet by Keystore
     */
    public Single<String> importFromKeystore(String keystore, String password, Context context) {
        return Single.fromCallable(() -> {
            try {
                Credentials credentials = CenterPrimeUtils.loadCredentials(password, keystore);
                String walletAddress = CenterPrimeUtils.generateWalletFile(password, credentials.getEcKeyPair(), new File(context.getFilesDir(), ""), false);

                return walletAddress;
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        });
    }

    private static final String HD_PATH = "44H/714H/0H/0/0";

    public static String getPrivateKeyFromMnemonicCode(List<String> words) {
        byte[] seed = MnemonicCode.toSeed(words, "");
        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(seed);

        List<ChildNumber> childNumbers = HDUtils.parsePath(HD_PATH);
        for (ChildNumber cn : childNumbers) {
            key = HDKeyDerivation.deriveChildKey(key, cn);
        }
        return key.getPrivateKeyAsHex();
    }


    public Single<Wallet> importFromMnemonic(List<String> words,
                                             String password,
                                             Context context) {

        String privateKey = getPrivateKeyFromMnemonicCode(words);

        return importFromPrivateKey(privateKey, context, password);
    }

    /**
     * Import Wallet with Private Key
     */
    public Single<Wallet> importFromPrivateKey(String privateKey, Context context, String password) {
        return Single.fromCallable(() -> {
            // Decode private key
            ECKeyPair keys = ECKeyPair.create(Hex.decode(privateKey));
            try {
                Credentials credentials = Credentials.create(keys);
                String walletAddress = CenterPrimeUtils.generateWalletFile(password, credentials.getEcKeyPair(), new File(context.getFilesDir(), ""), false);

                String walletPath = context.getFilesDir() + "/" + walletAddress.toLowerCase();
                File keystoreFile = new File(walletPath);
                String keystore = read_file(context, keystoreFile.getName());

                return new Wallet(walletAddress, keystore);
            } catch (CipherException | IOException e) {
                e.printStackTrace();
            }
            return null;
        });
    }

    /**
     * Export Private Key
     */
    public Single<String> exportPrivateKey(String walletAddress, String password, Context context) {
        return loadCredentials(walletAddress, password, context)
                .flatMap(credentials -> {
                    String privateKey = credentials.getEcKeyPair().getPrivateKey().toString(16);

                    return Single.just(privateKey);
                });
    }

    /**
     * Get BNB Balance of Wallet
     */
    public Single<BigDecimal> getBNBBalance(String address, Context context) {
        return Single.fromCallable(() -> {

            BigInteger valueInWei = web3j
                    .ethGetBalance(address, DefaultBlockParameterName.LATEST)
                    .send()
                    .getBalance();
            return BalanceUtils.weiToEth(valueInWei);
        });
    }


    /**
     * Load Credentials
     */
    public Single<Credentials> loadCredentials(String walletAddress, String password, Context context) {
        return getKeyStore(walletAddress, context)
                .flatMap(keystore -> {
                    try {
                        Credentials credentials = CenterPrimeUtils.loadCredentials(password, keystore);
                        return Single.just(credentials);
                    } catch (IOException e) {
                        e.printStackTrace();
                        return Single.error(e);
                    } catch (CipherException e) {
                        e.printStackTrace();
                        return Single.error(e);
                    }
                });
    }

    /**
     * Add Custom Token
     */
    public Single<Token> searchTokenByContractAddress(String contractAddress, String walletAddress, String password, Context context) {
        return loadCredentials(walletAddress, password, context)
                .flatMap(credentials -> {
                    TransactionReceiptProcessor transactionReceiptProcessor = new NoOpProcessor(web3j);
                    TransactionManager transactionManager = new RawTransactionManager(
                            web3j, credentials, isMainNet() ? (byte) 56 : (byte) 97, transactionReceiptProcessor);
                    Erc20TokenWrapper contract = Erc20TokenWrapper.load(contractAddress, web3j, transactionManager, BigInteger.ZERO, BigInteger.ZERO);
                    String tokenName = contract.name().getValue();
                    String tokenSymbol = contract.symbol().getValue();
                    BigInteger decimalCount = contract.decimals().getValue();

                    return Single.just(new Token(contractAddress, tokenSymbol, tokenName, decimalCount.toString()));
                });

    }

    /**
     * Get BEP20 Token Balance of Wallet
     */
    public Single<BigDecimal> getTokenBalance(String walletAddress, String password, String tokenContractAddress, Context context) {
        return loadCredentials(walletAddress, password, context)
                .flatMap(credentials -> {

                    TransactionReceiptProcessor transactionReceiptProcessor = new NoOpProcessor(web3j);
                    TransactionManager transactionManager = new RawTransactionManager(
                            web3j, credentials, isMainNet() ? (byte) 56 : (byte) 97, transactionReceiptProcessor);
                    Erc20TokenWrapper contract = Erc20TokenWrapper.load(tokenContractAddress, web3j,
                            transactionManager, BigInteger.ZERO, BigInteger.ZERO);
                    Address address = new Address(walletAddress);
                    BigInteger tokenBalance = contract.balanceOf(address).getValue();
                    BigInteger decimalCount = contract.decimals().getValue();

                    BigDecimal tokenValueByDecimals = BalanceUtils.balanceByDecimal(tokenBalance, decimalCount);

                    return Single.just(tokenValueByDecimals);
                });
    }

    /**
     * Send BNB
     */
    public Single<String> sendBNB(String walletAddress, String password,
                                  BigInteger gasPrice,
                                  BigInteger gasLimit,
                                  BigDecimal bnbAmount,
                                  String to_Address,
                                  Context context) {
        return loadCredentials(walletAddress, password, context)
                .flatMap(credentials -> {

                    BigInteger nonce = getNonce(walletAddress);
                    BigDecimal weiValue = Convert.toWei(bnbAmount, Convert.Unit.ETHER);

                    RawTransaction rawTransaction = RawTransaction.createEtherTransaction(
                            nonce, gasPrice, gasLimit, to_Address, weiValue.toBigIntegerExact());
                    byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
                    String hexValue = Numeric.toHexString(signedMessage);

                    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).sendAsync().get();

                    String transactionHash = ethSendTransaction.getTransactionHash();

                    return Single.just(transactionHash);
                });
    }

    /**
     * Send Token
     */
    public Single<String> sendToken(String walletAddress, String password,
                                    BigInteger gasPrice,
                                    BigInteger gasLimit,
                                    BigDecimal tokenAmount,
                                    String to_Address,
                                    String tokenContractAddress,
                                    Context context) {
        return loadCredentials(walletAddress, password, context)
                .flatMap(credentials -> {
                    TransactionReceiptProcessor transactionReceiptProcessor = new NoOpProcessor(web3j);
                    TransactionManager transactionManager = new RawTransactionManager(
                            web3j, credentials, isMainNet() ? (byte) 56 : (byte) 97, transactionReceiptProcessor);
                    Erc20TokenWrapper contract = Erc20TokenWrapper.load(tokenContractAddress, web3j, transactionManager, gasPrice, gasLimit);

                    BigInteger decimalCount = contract.decimals().getValue();

                    BigDecimal formattedAmount = BalanceUtils.amountByDecimal(tokenAmount, new BigDecimal(decimalCount));

                    TransactionReceipt mReceipt = contract.transfer(new Address(to_Address), new Uint256(formattedAmount.toBigInteger()));

                    return Single.just(mReceipt.getTransactionHash());
                });
    }


    /**
     * Get Nonce for Current Wallet Address
     */
    protected BigInteger getNonce(String walletAddress) throws IOException {
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                walletAddress, DefaultBlockParameterName.PENDING).send();

        return ethGetTransactionCount.getTransactionCount();
    }

    public String read_file(Context context, String filename) throws IOException {
        FileInputStream fis = context.openFileInput(filename);
        InputStreamReader isr = new InputStreamReader(fis, "UTF-8");
        BufferedReader bufferedReader = new BufferedReader(isr);
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }


    private boolean isMainNet() {
        return mainnetInfuraUrl.equals("https://bsc-dataseed1.binance.org:443");
    }
}
