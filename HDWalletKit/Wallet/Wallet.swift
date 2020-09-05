//
//  Wallet.swift
//  WalletKit
//
//  Created by yuzushioh on 2018/01/01.
//  Copyright © 2018 yuzushioh. All rights reserved.
//
import Foundation

@objc public final class  Wallet :NSObject {
    
    public let privateKey: PrivateKey
    public let coin: Coin
    
    public init(seed: Data, coin: Coin) {
        self.coin = coin
        privateKey = PrivateKey(seed: seed, coin: coin)
    }
    
    //MARK: - Public
    public func generateAddress(at index: UInt32)  -> String {
        let derivedKey = bip44PrivateKey.derived(at: .notHardened(index))
        return derivedKey.publicKey.address
    }
    
    public func generateAccount(at derivationPath: [DerivationNode]) -> Account {
        let privateKey = generatePrivateKey(at: derivationPath)
        return Account(privateKey: privateKey)
    }
    
    public func generateAccount(at index: UInt32 = 0) -> Account {
        let address = bip44PrivateKey.derived(at: .notHardened(index))
        return Account(privateKey: address)
    }
    
    public func generateAccounts(count: UInt32) -> [Account]  {
        var accounts:[Account] = []
        for index in 0..<count {
            accounts.append(generateAccount(at: index))
        }
        return accounts
    }
    
    public func sign(rawTransaction: EthereumRawTransaction) throws -> String {
        let signer = EIP155Signer(chainId: 1)
        let rawData = try signer.sign(rawTransaction, privateKey: privateKey)
        let hash = rawData.toHexString().addHexPrefix()
        return hash
    }
    
    @objc class public func generateBitcoinAccount() -> [String:String] {
        let mnemonic = Mnemonic.create()
        let seed = Mnemonic.createSeed(mnemonic: mnemonic)
        let wallet = Wallet(seed: seed, coin: .bitcoin)
        let account = wallet.generateAccount()
        return ["mnemonicKey":mnemonic,"addressKey":account.address,"privateKey":account.rawPrivateKey]
    }

    @objc class public func generateETHAccount() -> [String:String] {
        let mnemonic = Mnemonic.create()
        let seed = Mnemonic.createSeed(mnemonic: mnemonic)
        let wallet = Wallet(seed: seed, coin: .ethereum)
        let account = wallet.generateAccount()
        return ["mnemonicKey":mnemonic,"addressKey":account.address,"privateKey":account.rawPrivateKey]
    }

    @objc class public func importETHAccountWithPriateKey(at privateKeyStr:String) -> [String:String] {
        if privateKeyStr.count < 40 {
           return ["error":"私钥长度不够"];
        }
        let privateKey = PrivateKey(pk: privateKeyStr, coin: .ethereum)
        return ["mnemonicKey":"","addressKey":privateKey!.publicKey.address,"privateKey":privateKeyStr]
    }

    @objc class public func importBitcoinAccountWithPriateKey(at privateKeyStr:String) -> [String:String] {
        if privateKeyStr.count < 40 {
           return ["error":"私钥长度不够"];
        }
        let privateKey = PrivateKey(pk: privateKeyStr, coin: .bitcoin)
        return ["mnemonicKey":"","addressKey":privateKey!.publicKey.address,"privateKey":privateKeyStr]
    }

    @objc class public func importETHAccountWithMnemonic(at mnemonic:String) -> [String:String] {
        let mnemonicCount = mnemonic.components(separatedBy: " ")
        if mnemonicCount.count < 12 {
            return ["error":"助记词个数不够"];
        }
        for (index) in mnemonicCount.enumerated() {
            let word:String = index.element
            if word.count == 0 {
               return ["error":"助记词长度不对"];
            }
        }
        let seed = Mnemonic.createSeed(mnemonic: mnemonic)
        let wallet = Wallet(seed: seed, coin: .ethereum)
        let account = wallet.generateAccount()
        return ["mnemonicKey":mnemonic,"addressKey":account.address,"privateKey":account.rawPrivateKey]
    }

    @objc class public func importBitcoinAccountWithMnemonic(at mnemonic:String) -> [String:String] {
        let mnemonicCount = mnemonic.components(separatedBy: " ")
        if mnemonicCount.count < 12 {
            return ["error":"助记词个数不够"];
        }
        for (index) in mnemonicCount.enumerated() {
            let word:String = index.element
            if word.count == 0 {
               return ["error":"助记词长度不对"];
            }
        }
        let seed = Mnemonic.createSeed(mnemonic: mnemonic)
        let wallet = Wallet(seed: seed, coin: .bitcoin)
        let account = wallet.generateAccount()
        return ["mnemonicKey":mnemonic,"addressKey":account.address,"privateKey":account.rawPrivateKey]
    }
    //MARK: - Private
    //https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    private var bip44PrivateKey:PrivateKey {
        let bip44Purpose:UInt32 = 44
        let purpose = privateKey.derived(at: .hardened(bip44Purpose))
        let coinType = purpose.derived(at: .hardened(coin.coinType))
        let account = coinType.derived(at: .hardened(0))
        let receive = account.derived(at: .notHardened(0))
        return receive
    }
    
    private func generatePrivateKey(at nodes:[DerivationNode]) -> PrivateKey {
        return privateKey(at: nodes)
    }
    
    private func privateKey(at nodes: [DerivationNode]) -> PrivateKey {
        var key: PrivateKey = privateKey
        for node in nodes {
            key = key.derived(at:node)
        }
        return key
    }
}
