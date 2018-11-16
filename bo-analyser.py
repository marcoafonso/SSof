#Projeto SSof
#Marco Afonso 84610
#Ricardo Ramalho 84623

import sys
import json

def openJsonFile(file):
    with open(file) as f:
        data = json.loads(f.read())
    return data

def outputJsonFile(data):
    return json.dumps(data,indent=4)


def addOrDeleteAndAdd(l, valueAddress, destAddress, idx):
    for i in range(len(l)):
        for j in range(len(l[i])):

            if l[i][j] == destAddress:
                del(l[i][j])
                break

    for i in range(len(l)):
        for j in range(len(l[i])):
            if l[i][j] == valueAddress:
                l[i].append(destAddress)


    return l

def returnIndex(l, var):

    for i in range(len(l)):
        for j in range(len(l[i])):
            if l[i][j] == var:
                return i
    return False


def returnParametros(nArgs, pos, bytes, addresses, instructions):
    v = ['rdi', 'rsi', 'rdx']

    v = v[0:nArgs]
    parametersLenght = {}
    counter = 0
    op = variablesState(pos, addresses, instructions)
    for par in v:
        if counter == nArgs:
            break
        idx = returnIndex(op, par)

        if type(idx) == bool:
            continue

        if type(idx) == int:
            parametersLenght[v[counter]] = bytes [idx]
            counter +=1

    return parametersLenght


def variablesState(pos, addresses, instructions):

    for i in range(len(instructions)):

        if (instructions[i]['op'] == 'mov' or instructions[i]['op'] == 'lea') and instructions[i]['pos'] <= pos:
            valueAddress = instructions[i]['args']['value'].strip("[]")
            destAddress = instructions[i]['args']['dest'].strip("[]")
            state = addOrDeleteAndAdd(addresses, valueAddress, destAddress, instructions[i]['pos'])

    return state

def returnInput(pos, instructions, nArgs):
    newValue = {}
    valor = int(instructions[pos-nArgs]['args']['value'], 16)
    newValue['valor'] = valor
    return newValue

def returnTypeAddress(l, types):
    return

def overflow(data):
    allAddresses = []
    allBytes = []
    allNames = []
    allTypes = []
    stackAddresses = []
    fgetsBefore = False
    fgetsValue = 0
    changedVariables = {}
    results = []
    for fun in data:
        variables = data[fun]['variables']
        instructions = data[fun]['instructions']
        for i in range(len(variables)):
            allAddresses.append([variables[i]['address']])
            allBytes.append(variables[i]['bytes'])
            allTypes.append(variables[i]['type'])
            allNames.append(variables[i]['name'])
            stackAddresses.append(int(variables[i]['address'].strip("rbp-"), 16))


    stackAddresses.sort(reverse=True)
    stackAddressesNova = []
    for e in stackAddresses:
        stackAddressesNova.append("rbp-" + hex(e))


    for i in range(len(instructions)):
        if instructions[i]['op'] == 'call':
            if instructions[i]['args']['fnname'] == '<gets@plt>':

                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                enderecoRdi = allAddresses[returnIndex(allAddresses, "rdi")][0]

                for j in range(len(stackAddressesNova)):
                    if stackAddressesNova[j] == enderecoRdi:
                        idx = j

                adds = stackAddressesNova[idx:]

                if len(adds) > 1 :
                    for k in range(1, len(adds)):
                        getsVarRes = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '', 'overflow_var': '', 'address': ''}
                        getsVarRes['vuln_function'] = fun
                        getsVarRes['fnname'] = 'gets'
                        getsVarRes['vulnerability'] = 'VAROVERFLOW'
                        getsVarRes['address'] = instructions[i]['address']

                        getsVarRes['overflown_var'] = allNames[returnIndex(allAddresses, adds[k])]
                        getsVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                        results.append(getsVarRes)
                getsRbpRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '',
                               'fnname': ''}
                getsRetRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '',
                               'fnname': ''}
                getsRbpRes['vuln_function'] = fun
                getsRbpRes['fnname'] = 'gets'
                getsRbpRes['vulnerability'] = 'RBPOVERFLOW'
                getsRbpRes['address'] = instructions[i]['address']
                getsRbpRes['overflow_var'] = allNames[returnIndex(allAddresses, adds[0])]
                getsRetRes['vuln_function'] = fun
                getsRetRes['fnname'] = 'gets'
                getsRetRes['vulnerability'] = 'RETOVERFLOW'
                getsRetRes['address'] = instructions[i]['address']
                getsRetRes['overflow_var'] = allNames[returnIndex(allAddresses, adds[0])]

                results.append(getsRbpRes)
                results.append(getsRetRes)

            if instructions[i]['args']['fnname'] == '<fgets@plt>':

                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                parameters.update(returnInput(instructions[i]['pos'], instructions, 2))
                enderecoRdi = allAddresses[returnIndex(allAddresses, "rdi")][0]

                fgetsValue = parameters["valor"]
                changedVariables[enderecoRdi] = fgetsValue
                for j in range(len(stackAddressesNova)):
                    if stackAddressesNova[j] == enderecoRdi:
                        idx = j

                adds = stackAddressesNova[idx:]


                for k in range(len(adds)):

                    if k + 1 < len(adds):

                        if int(adds[0].strip("rbp"), 16) + fgetsValue > int(adds[k+1].strip("rbp"), 16) :

                            fgetsVarRes = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '','overflow_var': '','address': ''}
                            fgetsVarRes['vuln_function'] = fun
                            fgetsVarRes['fnname'] = 'fgets'
                            fgetsVarRes['vulnerability'] = 'VAROVERFLOW'
                            fgetsVarRes['address'] = instructions[i]['address']

                            fgetsVarRes['overflown_var'] = allNames[returnIndex(allAddresses,adds[k + 1])]
                            fgetsVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                            results.append(fgetsVarRes)


                if int(adds[0].strip("rbp"), 16) + fgetsValue > 0 :
                    fgetsRbpRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '', 'fnname': ''}
                    fgetsRbpRes['vuln_function'] = fun
                    fgetsRbpRes['fnname'] = 'fgets'
                    fgetsRbpRes['vulnerability'] = 'RBPOVERFLOW'
                    fgetsRbpRes['address'] = instructions[i]['address']
                    fgetsRbpRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(fgetsRbpRes)



                if int(adds[0].strip("rbp"), 16) + fgetsValue > 8 :
                    fgetsRetRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '',  'fnname': ''}
                    fgetsRetRes['vuln_function'] = fun
                    fgetsRetRes['fnname'] = 'fgets'
                    fgetsRetRes['vulnerability'] = 'RETOVERFLOW'
                    fgetsRetRes['address'] = instructions[i]['address']
                    fgetsRetRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(fgetsRetRes)




            if instructions[i]['args']['fnname'] == '<strcpy@plt>':

                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)

                enderecoRdi = allAddresses[returnIndex(allAddresses, "rdi")][0]
                enderecoRsi = allAddresses[returnIndex(allAddresses, "rsi")][0]

                fgetsValue = parameters['rsi']

                if enderecoRsi in changedVariables:
                    fgetsValue = changedVariables[enderecoRsi]

                for j in range(len(stackAddressesNova)):
                    if stackAddressesNova[j] == enderecoRdi:
                        idx = j

                adds = stackAddressesNova[idx:]


                for k in range(len(adds)):

                    if k + 1 < len(adds):

                        if int(adds[0].strip("rbp"), 16) + fgetsValue > int(adds[k + 1].strip("rbp"), 16):

                            strcpyVarRes = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '', 'overflow_var': '', 'address': ''}
                            strcpyVarRes['vuln_function'] = fun
                            strcpyVarRes['fnname'] = 'strcpy'
                            strcpyVarRes['vulnerability'] = 'VAROVERFLOW'
                            strcpyVarRes['address'] = instructions[i]['address']

                            strcpyVarRes['overflown_var'] = allNames[returnIndex(allAddresses, adds[k + 1])]
                            strcpyVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                            results.append(strcpyVarRes)

                if int(adds[0].strip("rbp"), 16) + fgetsValue > 0 :
                    strcpyRbpRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '', 'fnname': ''}
                    strcpyRbpRes['vuln_function'] = fun
                    strcpyRbpRes['fnname'] = 'strcpy'
                    strcpyRbpRes['vulnerability'] = 'RBPOVERFLOW'
                    strcpyRbpRes['address'] = instructions[i]['address']
                    strcpyRbpRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strcpyRbpRes)


                if int(adds[0].strip("rbp"), 16) + fgetsValue > 8 :
                    strcpyRetRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '','fnname': ''}
                    strcpyRetRes['vuln_function'] = fun
                    strcpyRetRes['fnname'] = 'strcpy'
                    strcpyRetRes['vulnerability'] = 'RETOVERFLOW'
                    strcpyRetRes['address'] = instructions[i]['address']
                    strcpyRetRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strcpyRetRes)


            if instructions[i]['args']['fnname'] == '<strncpy@plt>':
                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                parameters.update(returnInput(instructions[i]['pos'], instructions, 3))

                enderecoRdi = allAddresses[returnIndex(allAddresses, "rdi")][0]
                enderecoRsi = allAddresses[returnIndex(allAddresses, "rsi")][0]

                fgetsValue = parameters['rsi']

                if enderecoRsi in changedVariables:
                    fgetsValue = changedVariables[enderecoRsi]

                for j in range(len(stackAddressesNova)):
                    if stackAddressesNova[j] == enderecoRdi:
                        idx = j
                fgetsValue = min(parameters['valor'], fgetsValue)

                adds = stackAddressesNova[idx:]


                for k in range(len(adds)):

                    if k + 1 < len(adds):

                        if int(adds[0].strip("rbp"), 16) + fgetsValue > int(adds[k + 1].strip("rbp"), 16):
                            strncpyVarRes = {'fnname': '', 'vuln_function': '', 'overflown_var': '','vulnerability': '', 'overflow_var': '', 'address': ''}
                            strncpyVarRes['vuln_function'] = fun
                            strncpyVarRes['fnname'] = 'strncpy'
                            strncpyVarRes['vulnerability'] = 'VAROVERFLOW'
                            strncpyVarRes['address'] = instructions[i]['address']
                            strncpyVarRes['overflown_var'] = allNames[returnIndex(allAddresses, adds[k + 1])]
                            strncpyVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                            results.append(strncpyVarRes)

                if int(adds[0].strip("rbp"), 16) + fgetsValue > 0 :

                    strncpyRbpRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '', 'fnname': ''}
                    strncpyRbpRes['vuln_function'] = fun
                    strncpyRbpRes['fnname'] = 'strncpy'
                    strncpyRbpRes['vulnerability'] = 'RBPOVERFLOW'
                    strncpyRbpRes['address'] = instructions[i]['address']
                    strncpyRbpRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strncpyRbpRes)

                if int(adds[0].strip("rbp"), 16) + fgetsValue > 8 :
                    strncpyRetRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '', 'fnname': ''}
                    strncpyRetRes['vuln_function'] = fun
                    strncpyRetRes['fnname'] = 'strncpy'
                    strncpyRetRes['vulnerability'] = 'RETOVERFLOW'
                    strncpyRetRes['address'] = instructions[i]['address']
                    strncpyRetRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strncpyRetRes)


            if instructions[i]['args']['fnname'] == '<strcat@plt>':
                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)

                enderecoRdi = allAddresses[returnIndex(allAddresses, "rdi")][0]
                enderecoRsi = allAddresses[returnIndex(allAddresses, "rsi")][0]

                fgetsValue = parameters['rsi']
                fgetsValue2 = parameters['rdi']


                if enderecoRsi in changedVariables:
                    fgetsValue = changedVariables[enderecoRsi]

                if enderecoRdi in changedVariables:
                    fgetsValue2 = changedVariables[enderecoRdi]

                for j in range(len(stackAddressesNova)):
                    if stackAddressesNova[j] == enderecoRdi:
                        idx = j


                adds = stackAddressesNova[idx:]


                for k in range(len(adds)):

                    if k + 1 < len(adds):

                        if int(adds[0].strip("rbp"), 16) + fgetsValue +  fgetsValue2 > int(adds[k + 1].strip("rbp"), 16):
                            strcatVarRes = {'fnname': '', 'vuln_function': '', 'overflown_var': '','vulnerability': '', 'overflow_var': '', 'address': ''}
                            strcatVarRes['vuln_function'] = fun
                            strcatVarRes['fnname'] = 'strcat'
                            strcatVarRes['vulnerability'] = 'VAROVERFLOW'
                            strcatVarRes['address'] = instructions[i]['address']

                            strcatVarRes['overflown_var'] = allNames[returnIndex(allAddresses, adds[k + 1])]
                            strcatVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                            results.append(strcatVarRes)

                if int(adds[0].strip("rbp"), 16) + fgetsValue +  fgetsValue2 > 0 :
                    strcatVarRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '', 'fnname': ''}
                    strcatVarRes['vuln_function'] = fun
                    strcatVarRes['fnname'] = 'strcat'
                    strcatVarRes['vulnerability'] = 'RBPOVERFLOW'
                    strcatVarRes['address'] = instructions[i]['address']
                    strcatVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strcatVarRes)


                if int(adds[0].strip("rbp"), 16) + fgetsValue +  fgetsValue2 > 8 :
                    strcatVarRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '', 'fnname': ''}
                    strcatVarRes['vuln_function'] = fun
                    strcatVarRes['fnname'] = 'strcat'
                    strcatVarRes['vulnerability'] = 'RETOVERFLOW'
                    strcatVarRes['address'] = instructions[i]['address']
                    strcatVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strcatVarRes)

            if instructions[i]['args']['fnname'] == '<strncat@plt>':
                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                parameters.update(returnInput(instructions[i]['pos'], instructions, 3))
                enderecoRdi = allAddresses[returnIndex(allAddresses, "rdi")][0]
                enderecoRsi = allAddresses[returnIndex(allAddresses, "rsi")][0]
                fgetsValue = parameters['rsi']
                fgetsValue2 = parameters['rdi']


                if enderecoRsi in changedVariables:
                    fgetsValue2 = changedVariables[enderecoRsi]

                if enderecoRdi in changedVariables:
                    fgetsValue = changedVariables[enderecoRdi]

                for j in range(len(stackAddressesNova)):
                    if stackAddressesNova[j] == enderecoRdi:
                        idx = j

                fgetsValue2 = min(parameters['valor'], fgetsValue2)
                adds = stackAddressesNova[idx:]

                for k in range(len(adds)):

                    if k + 1 < len(adds):
                        if int(adds[0].strip("rbp"), 16) + fgetsValue + fgetsValue2 > int(adds[k + 1].strip("rbp"), 16):
                            strncatVarRes = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '',
                                            'overflow_var': '', 'address': ''}
                            strncatVarRes['vuln_function'] = fun
                            strncatVarRes['fnname'] = 'strncat'
                            strncatVarRes['vulnerability'] = 'VAROVERFLOW'
                            strncatVarRes['address'] = instructions[i]['address']

                            strncatVarRes['overflown_var'] = allNames[returnIndex(allAddresses, adds[k + 1])]
                            strncatVarRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                            results.append(strncatVarRes)

                if int(adds[0].strip("rbp"), 16) + fgetsValue + fgetsValue2 > 0:
                    strncatRbpRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '',
                                    'fnname': ''}
                    strncatRbpRes['vuln_function'] = fun
                    strncatRbpRes['fnname'] = 'strncat'
                    strncatRbpRes['vulnerability'] = 'RBPOVERFLOW'
                    strncatRbpRes['address'] = instructions[i]['address']
                    strncatRbpRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]
                    results.append(strncatRbpRes)

                if int(adds[0].strip("rbp"), 16) + fgetsValue + fgetsValue2 > 8:
                    strncatRetRes = {'vulnerability': '', 'overflow_var': '', 'vuln_function': '', 'address': '',
                                    'fnname': ''}
                    strncatRetRes['vuln_function'] = fun
                    strncatRetRes['fnname'] = 'strncat'
                    strncatRetRes['vulnerability'] = 'RETOVERFLOW'
                    strncatRetRes['address'] = instructions[i]['address']
                    strncatRetRes['overflow_var'] = allNames[returnIndex(allAddresses, enderecoRdi)]

                    results.append(strncatRetRes)
    return results


def usage(progName):
    print('Seguranca em Software - Instituto Superior Tecnico / Universidade Lisboa')
    print('Buffer Overflow Analyser: Shows Buffer Overflow vulnerabilities.\n')
    print('')
    print('Usage:')
    print('  %s <program>.json' % progName)
    print('')
    sys.exit()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(sys.argv[0])
    data = str(sys.argv[1]) if len(sys.argv) == 2 else 0
    d = openJsonFile(data)
    d = outputJsonFile(overflow(d))
    f = open(data.strip('.json') + '.output.json', 'w')
    print(d, file=f)



