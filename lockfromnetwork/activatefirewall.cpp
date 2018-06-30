#include "stdafx.h"
#include "activatefirewall.h"

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <netfw.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


int __cdecl activatefirewall::firewall(){


	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	INetFwPolicy2 *pNetFwPolicy2 = NULL;
	INetFwRules *pFwRules = NULL;
	INetFwRule *pFwRule = NULL;

	long CurrentProfilesBitMask = 0;

	BSTR bstrRuleName = SysAllocString(L"TEST_OUTBOUND_RULE");
	BSTR bstrRuleDescription = SysAllocString(L"Allow outbound network traffic from my Application over TCP port 4000");
	BSTR bstrRuleGroup = SysAllocString(L"Test Group");
	//BSTR bstrRuleApplication = SysAllocString(L"Any");
	BSTR bstrRuleLPorts = SysAllocString(L"4000");

	// Forward declarations
	HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);


		// Initialize COM.
		hrComInit = CoInitializeEx(
			0,
			COINIT_APARTMENTTHREADED
		);

		// Retrieve INetFwPolicy2
		hr = WFCOMInitialize(&pNetFwPolicy2);
		if (FAILED(hr))
		{
			goto Cleanup;
		}

		// Retrieve INetFwRules
		hr = pNetFwPolicy2->get_Rules(&pFwRules);
		if (FAILED(hr))
		{
			printf("get_Rules failed: 0x%08lx\n", hr);
			goto Cleanup;
		}

		// Retrieve Current Profiles bitmask
		hr = pNetFwPolicy2->get_CurrentProfileTypes(&CurrentProfilesBitMask);
		if (FAILED(hr))
		{
			printf("get_CurrentProfileTypes failed: 0x%08lx\n", hr);
			goto Cleanup;
		}

		// When possible we avoid adding firewall rules to the Public profile.
		// If Public is currently active and it is not the only active profile, we remove it from the bitmask
		if ((CurrentProfilesBitMask & NET_FW_PROFILE2_PUBLIC) &&
			(CurrentProfilesBitMask != NET_FW_PROFILE2_PUBLIC))
		{
			CurrentProfilesBitMask ^= NET_FW_PROFILE2_PUBLIC;
		}

		// Create a new Firewall Rule object.
		hr = CoCreateInstance(
			__uuidof(NetFwRule),
			NULL,
			CLSCTX_INPROC_SERVER,
			__uuidof(INetFwRule),
			(void**)&pFwRule);
		if (FAILED(hr))
		{
			printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
			goto Cleanup;
		}

		// Populate the Firewall Rule object
		pFwRule->put_Name(bstrRuleName);
		pFwRule->put_Description(bstrRuleDescription);
		//pFwRule->put_ApplicationName(bstrRuleApplication);
		pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
		pFwRule->put_LocalPorts(bstrRuleLPorts);
		pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
		pFwRule->put_Grouping(bstrRuleGroup);
		pFwRule->put_Profiles(CurrentProfilesBitMask);
		pFwRule->put_Action(NET_FW_ACTION_BLOCK);
		pFwRule->put_Enabled(VARIANT_TRUE);

		// Add the Firewall Rule
		hr = pFwRules->Add(pFwRule);
		if (FAILED(hr))
		{
			printf("Firewall Rule Add failed: 0x%08lx\n", hr);
			goto Cleanup;
		}

	Cleanup:

		// Free BSTR's
		SysFreeString(bstrRuleName);
		SysFreeString(bstrRuleDescription);
		SysFreeString(bstrRuleGroup);
		//SysFreeString(bstrRuleApplication);
		SysFreeString(bstrRuleLPorts);

		// Release the INetFwRule object
		if (pFwRule != NULL)
		{
			pFwRule->Release();
		}

		// Release the INetFwRules object
		if (pFwRules != NULL)
		{
			pFwRules->Release();
		}

		// Release the INetFwPolicy2 object
		if (pNetFwPolicy2 != NULL)
		{
			pNetFwPolicy2->Release();
		}

		// Uninitialize COM.
		if (SUCCEEDED(hrComInit))
		{
			CoUninitialize();
		}

		return 0;

}

// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;

	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)ppNetFwPolicy2);

	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:
	return hr;
}