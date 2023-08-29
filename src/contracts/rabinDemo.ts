import { assert, ByteString, method, prop, SmartContract } from 'scrypt-ts'
import { RabinPubKey, RabinSig, RabinVerifierWOC } from 'scrypt-ts-lib'

export class RabinDemo extends SmartContract {
    @prop()
    pubKey: RabinPubKey

    constructor() {
        super(...arguments)
        this.pubKey = 806601590652956834018399678533433330297520166170621677718366777282597008261175369958720728325788781957301517421248979722124322014908005896229583387020751139752183740977977992209086123038969731450485318947788672763297547761693887724241199326085478474318421040040373573386924621067572175562203673198539124398617643535974063533030798711728926101490992140759381047314622647708525546076184615618641756952860677648413425031093445751156507332437310584683508880247430736178789021942005256459521793630277903367137027423426709231650428666408539139818974046833782009405081791441480798034660675416464075370612712674283657014595582339399258746911970999875576511830555755483835968845457351790361636021818838815015367880928091532562125760181215916964503709203093555467749323005045402306132828909170770279954434996949977916140155679733009945879625068160387460924966567486357375120600807460265701518792043161343124480625464663427359655993589n
    }

    @method()
    public unlock(msg: ByteString, sig: RabinSig) {
        console.log('unlock start')
        assert(true)
        console.log('unlock running 1')
        assert(
            RabinVerifierWOC.verifySig(msg, sig, this.pubKey),
            'rabin signature verified failed'
        )
        console.log('unlock running 2')
        assert(true)
        console.log('unlock end')
    }
}