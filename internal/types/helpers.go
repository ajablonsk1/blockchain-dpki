package types

func (tx *Transaction) BodyType() string {
	if tx == nil {
		return ""
	}

	switch tx.GetBody().(type) {
	case *Transaction_Register:
		return "register"
	case *Transaction_Revoke:
		return "revoke"
	case *Transaction_Rotate:
		return "rotate"
	case nil:
		return ""
	default:
		return ""
	}
}

func (tx *Transaction) GetDomainFromBody() string {
	if tx == nil {
		return ""
	}

	switch body := tx.GetBody().(type) {
	case *Transaction_Register:
		return body.Register.GetCertificate().GetDomain()
	case *Transaction_Revoke:
		return body.Revoke.GetDomain()
	case *Transaction_Rotate:
		return body.Rotate.GetDomain()
	case nil:
		return ""
	default:
		return ""
	}
}
