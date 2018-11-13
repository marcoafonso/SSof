#Projeto SSof
#Marco Afonso 84610
#Ricardo Ramalho 84623

import sys
import json
import sys

#Output Variables
overflown_address = ''
fnname = ''
vuln_function = ''
address = ''
vulnerability = ''
overflow_var = ''
overflown_var = ''

#funcao auxiliar explicar
def openJsonFile(file):
    with open(file) as f:
        data = json.loads(f.read())
    return data

#funcao auxiliar explicar
def outputJsonFile(data):
    data = [data]
    return json.dumps(data)


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
    op = variablesState(pos, bytes, addresses, instructions)
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




def variablesState(pos, bytes, addresses, instructions):

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





def varOverflow(data):
    res = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '', 'overflow_var': '', 'address': ''}
    #registos

    allAddresses = []
    allBytes = []
    res2 = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '', 'overflow_var': '', 'address': ''}
    res3 = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '', 'overflow_var': '',
            'address': ''}

    for fun in data:
        variables = data[fun]['variables']
        instructions = data[fun]['instructions']
        for i in range(len(variables)):
            allAddresses.append([variables[i]['address']])
            allBytes.append(variables[i]['bytes'])
            if variables[i]['type'] == 'buffer':
                res['overflow_var'] = variables[i]['name']
                res2['overflow_var'] = variables[i]['name']
                res3['overflow_var'] = variables[i]['name']
            if variables[i]['type'] != 'buffer':
                res['overflown_var'] = variables[i]['name']
                res2['overflown_var'] = variables[i]['name']
                res3['overflown_var'] = variables[i]['name']
                continue


    for i in range(len(instructions)):
        if instructions[i]['op'] == 'call':
            if instructions[i]['args']['fnname'] == '<gets@plt>':
                res['vuln_function'] = fun
                res['fnname'] = 'gets'
                res['vulnerability'] = 'VAROVERFLOW'
                res['address'] = instructions[i]['address']
            if instructions[i]['args']['fnname'] == '<strcpy@plt>':
                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                print (parameters)
                if parameters["rsi"] > parameters["rdi"]:
                    res['vuln_function'] = fun
                    res['fnname'] = 'strcpy'
                    res['vulnerability'] = 'VAROVERFLOW'
                    res['address'] = instructions[i]['address']

            if instructions[i]['args']['fnname'] == '<fgets@plt>':
                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                parameters.update(returnInput(instructions[i]['pos'], instructions, 2))
                print(parameters)
                if parameters["valor"] > parameters["rdi"]:
                    res2['vuln_function'] = fun
                    res2['fnname'] = 'fgets'
                    res2['vulnerability'] = 'VAROVERFLOW'
                    res2['address'] = instructions[i]['address']

            if instructions[i]['args']['fnname'] == '<strncpy@plt>':
                parameters = returnParametros(2, instructions[i]['pos'] - 1, allBytes, allAddresses, instructions)
                parameters.update(returnInput(instructions[i]['pos'], instructions, 3))
                print(parameters)
                if parameters["valor"] > parameters["rdi"]:
                    res3['vuln_function'] = fun
                    res3['fnname'] = 'strncpy'
                    res3['vulnerability'] = 'VAROVERFLOW'
                    res3['address'] = instructions[i]['address']




    print (res)
    print(res2)
    print(res3)
#print (operations)


d = openJsonFile('07_fgets_strncpy_varoverflow.json')
print (d)
varOverflow(d)

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
    d = outputJsonFile(varOverflow(d))
    f = open(data.strip('.json') + '.output.json', 'w')
    print(d, file = f)



