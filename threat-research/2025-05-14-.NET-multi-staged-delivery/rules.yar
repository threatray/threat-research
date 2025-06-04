import "dotnet"

rule multi_layer_loader_3rd_stage {
  meta:
    description = "Detects third stage multi-layer .NET loader" 
    date = "2025-05-09"
    author = "Threatray (David Pastor)"
    hash = "063ca3294442e1194f637e02186e9682f3872c59e6247b8a8c759e9cba936669, 873eb1535c73bab017c8e351443519d576761c759884ea95e32d3ed26173fddc, d3987a5d9cb294e7cc7990c9a45b2a080dc99aa7b61fc4c9e437fc4659effda7, 7532336b3fb752a7fa95aa1da5ddc527600d0cbba1aa2d77b46052439a32e619, 685478424a00d7690aad5768bf08e9a61f335dae5706eebf23e612b6d2cacdf8, f6ae4366b5e0ae5e46c9c1ec6045cdfec80fed0e3292f3275a74f81800109d42, 052efeadeb1533936df0a1656b6f2f59f47ef10698274356e3231099f87427c4, 401ed7a01b85082da8ab1d2400a209724353af167100a98b864b4e7365daf4e9"
  
  strings:
    /**
    28 ?? 0? 00 06      call     class [mscorlib]System.Reflection.MethodInfo
    14                  ldnull
    11 0?               ldloc.s  1
    **/
    $func1_1 = {28 ?? 0? 00 06 14 11 0?}
    
    /**
    17                  ldc.i4.1
    8D 1? 00 00 01      newarr   [mscorlib]System.Object
    25                  dup
    16                  ldc.i4.0
    17                  ldc.i4.1
    8D 0? 00 00 01      newarr   [mscorlib]System.String
    A2                  stelem.ref
    13 01               stloc.s  1
    38 CB FF FF FF      br       
    **/
    $func1_2 = {17 8D 1? 00 00 01 25 16 17 8D 0? 00 00 01 A2 13 01 38}
    
    /**
    7E 69 00 00 04      ldsfld   unsigned int8[]
    28 ?? 0? 00 0?      call     class [mscorlib]System.Reflection.Assembly
    13 00               stloc.s  0
    **/
    $func1_3 = {7E ( 36 | 69 ) 00 00 04 ( 7E | 28 ) ?? 0? 00 0? ( 28 D? 04 00 06 13 00 | 13 00 )}
    
    /**
    38 00 00 00 00                    br      
    00                                nop
    16                                ldc.i4.0
    28 ?? 0? 00 06                    call     class [mscorlib]System.Reflection.Assembly
    28 ?? 01 00 06                    call     string
    28 ?? 0? 00 06                    call     void
    38 00 00 00 00                    br       
    00                                nop
    00                                nop
    DD ?? ?? ?? ??                    leave
    38 ?? ?? ?? ??
    **/
    $func1_4 = {( 38 ( 00 00 00 00 | 00 00 00 00 00 ) 16  | 7E D3 01 00 04 ) 28 ?? 0? 00 06 ( 28 ?? 01 00 06 | 7E BA 02 00 04 ) 28 ?? 0? 00 06 38 00 00 00 00 ( DD | 00 DD | 00 00 DD ) ?? ?? ?? ?? 38}
  
  condition:
    dotnet.is_dotnet and all of them
}