"""Metadata scope tests supplement, rather than replace, actual model evaluation."""
from scripts.evaluate_pe_test import applicability


def row():
    return {'header': {'coff': {'machine':'IMAGE_FILE_MACHINE_I386'},
        'optional': {'magic':267,'subsystem':'IMAGE_SUBSYSTEM_WINDOWS_GUI'}},
        'datadirectories':[{'name':'COM_DESCRIPTOR','size':0,'virtual_address':0}]}


def test_native_header_proxy_accepts_supported_format():
    assert applicability(row())


def test_managed_metadata_is_outside_live_scope():
    data=row();data['datadirectories'][0]['virtual_address']=100
    assert not applicability(data)


def test_driver_metadata_is_outside_live_scope():
    data=row();data['header']['optional']['subsystem']='IMAGE_SUBSYSTEM_NATIVE'
    assert not applicability(data)


def test_missing_header_is_unknown_live_scope_not_an_inference_error():
    data=row();data['header']={}
    assert not applicability(data)
