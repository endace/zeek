// See the file "COPYING" in the main distribution directory for copyright.

// Classes for tracking information for initializing C++ globals used by the
// generated code.

#include "zeek/Val.h"
#include "zeek/File.h"

#pragma once

namespace zeek::detail
	{

class CPPCompile;

// Abstract class for tracking the information about a single global.
// This might be a stand-alone global, or a global that's ultimately
// instantiated as part of a CPP_Globals object.
class CPP_GlobalInfo;

// Abstract class for tracking the information about a set of globals,
// each of which is an element of a CPP_Globals object.
class CPP_GlobalsInfo
	{
public:
	CPP_GlobalsInfo(std::string _tag, std::string type)
		: tag(std::move(_tag))
		{
		base_name = std::string("CPP__") + tag + "__";
		CPP_type = tag + type;
		}

	virtual ~CPP_GlobalsInfo() { }

	std::string InitializersName() const { return base_name + "init"; }
	const std::string& GlobalsName() const { return base_name; }

	std::string Name(int index) const;
	std::string NextName() const { return Name(Size()); }

	int Size() const { return size; }
	int MaxCohort() const { return static_cast<int>(instances.size()) - 1; }

	const std::string& Tag() const { return tag; }
	const std::string& CPPType() const { return CPP_type; }

	void AddInstance(std::shared_ptr<CPP_GlobalInfo> g);

	std::string Declare() const;

	void GenerateInitializers(CPPCompile* c);

protected:
	int size = 0;	// total number of globals

	// The outer vector is indexed by initialization cohort.
	std::vector<std::vector<std::shared_ptr<CPP_GlobalInfo>>> instances;

	// Tag used to distinguish a particular set of constants.
	std::string tag;

	// C++ name for this set of constants.
	std::string base_name;

	// C++ type associated with a single instance of these constants.
	std::string CPP_type;
	};


class CPP_GlobalInfo
	{
public:
	// Constructor used for stand-alone globals.  The second
	// argument specifies the core of the associated type.
	CPP_GlobalInfo(std::string _name, std::string _type)
		: name(std::move(_name)), type(std::move(_type))
		{ }

	// Constructor used for a global that will be part of a CPP_GlobalsInfo
	// object.  The rest of its initialization will be done by
	// CPP_GlobalsInfo::AddInstance.
	CPP_GlobalInfo() { }

	virtual ~CPP_GlobalInfo() { }

	int Offset() const { return offset; }
	void SetOffset(const CPP_GlobalsInfo* _gls, int _offset)
		{
		gls = _gls;
		offset = _offset;
		}

	// Returns the name that should be used for referring to this
	// global in the generated code.
	std::string Name() const { return gls ? gls->Name(offset) : name; }

	int InitCohort() const { return init_cohort; }

	// Returns a C++ declaration for this global.  Not used if
	// the global is part of a CPP_Globals object.
	std::string Declare() const { return type + " " + Name() + ";"; }

	// Returns a C++ initialization for creating this global.
	virtual std::string Initializer() const = 0;

protected:
	std::string name;
	std::string type;

	// By default, globals have no dependencies on other globals
	// being first initialized.  Those that do must increase this
	// value in their constructors.
	int init_cohort = 0;

	const CPP_GlobalsInfo* gls = nullptr;
	int offset = -1;	// offset for CPP_GlobalsInfo, if non-nil
	};


class BoolConstantInfo : public CPP_GlobalInfo
	{
public:
	BoolConstantInfo(ValPtr v) : b(v->AsBool()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_BoolConst(") + (b ? "true" : "false") + ")";
		}

private:
	bool b;
	};

class IntConstantInfo : public CPP_GlobalInfo
	{
public:
	IntConstantInfo(ValPtr v) : i(v->AsInt()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_IntConst(") + std::to_string(i) + ")";
		}

private:
	bro_int_t i;
	};

class CountConstantInfo : public CPP_GlobalInfo
	{
public:
	CountConstantInfo(ValPtr v) : u(v->AsCount()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_CountConst(") + std::to_string(u) + ")";
		}

private:
	bro_uint_t u;
	};

class EnumConstantInfo : public CPP_GlobalInfo
	{
public:
	EnumConstantInfo(CPPCompile* c, ValPtr v);

	std::string Initializer() const override
		{
		return std::string("CPP_EnumConst(") + std::to_string(e_type) + ", " + std::to_string(e_val) + ")";
		}

private:
	int e_type;
	int e_val;
	};

class DoubleConstantInfo : public CPP_GlobalInfo
	{
public:
	DoubleConstantInfo(ValPtr v) : d(v->AsDouble()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_DoubleConst(") + std::to_string(d) + ")";
		}

private:
	double d;
	};

class TimeConstantInfo : public CPP_GlobalInfo
	{
public:
	TimeConstantInfo(ValPtr v) : d(v->AsTime()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_TimeConst(") + std::to_string(d) + ")";
		}

private:
	double d;
	};

class IntervalConstantInfo : public CPP_GlobalInfo
	{
public:
	IntervalConstantInfo(ValPtr v) : d(v->AsInterval()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_IntervalConst(") + std::to_string(d) + ")";
		}

private:
	double d;
	};

class StringConstantInfo : public CPP_GlobalInfo
	{
public:
	StringConstantInfo(ValPtr v);

	std::string Initializer() const override;

private:
	std::string rep;
	int len;
	};

class PatternConstantInfo : public CPP_GlobalInfo
	{
public:
	PatternConstantInfo(ValPtr v);

	std::string Initializer() const override;

private:
	std::string pattern;
	int is_case_insensitive;
	};

class DescConstantInfo : public CPP_GlobalInfo
	{
public:
	DescConstantInfo(ValPtr v);

	std::string Initializer() const override;

private:
	std::string init;
	};

class PortConstantInfo : public CPP_GlobalInfo
	{
public:
	PortConstantInfo(ValPtr v) : p(static_cast<UnsignedValImplementation*>(v->AsPortVal())->Get()) { }

	std::string Initializer() const override
		{
		return std::string("CPP_PortConst(") + std::to_string(p) + ")";
		}

private:
	bro_uint_t p;
	};

class ListConstantInfo : public CPP_GlobalInfo
	{
public:
	ListConstantInfo(CPPCompile* c, ValPtr v);

	std::string Initializer() const override;

private:
	std::string vals;
	};

class VectorConstantInfo : public CPP_GlobalInfo
	{
public:
	VectorConstantInfo(CPPCompile* c, ValPtr v);

	std::string Initializer() const override
		{
		return std::string("CPP_VectorConst(") + std::to_string(yield) + ", { " + vals + "})";
		}

private:
	int yield;
	std::string vals;
	};

class RecordConstantInfo : public CPP_GlobalInfo
	{
public:
	RecordConstantInfo(CPPCompile* c, ValPtr v);

	std::string Initializer() const override
		{
		return std::string("CPP_RecordConst(") + std::to_string(type) + ", { " + vals + "})";
		}

private:
	int type;
	std::string vals;
	};

class TableConstantInfo : public CPP_GlobalInfo
	{
public:
	TableConstantInfo(CPPCompile* c, ValPtr v);

	std::string Initializer() const override
		{
		return std::string("CPP_TableConst(") + std::to_string(type) + ", { " + indices + "}, { " + vals + "})";
		}

private:
	int type;
	std::string indices;
	std::string vals;
	};

class FileConstantInfo : public CPP_GlobalInfo
	{
public:
	FileConstantInfo(CPPCompile* c, ValPtr v)
		: CPP_GlobalInfo(), name(cast_intrusive<FileVal>(v)->Get()->Name())
		{ }

	std::string Initializer() const override
		{
		return std::string("CPP_FileConst(\"") + name + "\")";
		}

private:
	std::string name;
	};

class FuncConstantInfo : public CPP_GlobalInfo
	{
public:
	FuncConstantInfo(CPPCompile* _c, ValPtr v)
		: CPP_GlobalInfo(), c(_c), f(v->AsFuncVal()) { }

	std::string Initializer() const override;

private:
	CPPCompile* c;
	FuncVal* f;
	};


class AttrInfo : public CPP_GlobalInfo
	{
public:
	AttrInfo(CPPCompile* c, const AttrPtr& attr);

	std::string Initializer() const override;

protected:
	std::string tag;
	std::string expr1, expr2;
	};

class AttrsInfo : public CPP_GlobalInfo
	{
public:
	AttrsInfo(CPPCompile* c, const AttributesPtr& attrs);

	std::string Initializer() const override;

protected:
	std::vector<int> attrs;
	};


class AbstractTypeInfo : public CPP_GlobalInfo
	{
public:
	AbstractTypeInfo(TypePtr _t) : CPP_GlobalInfo(), t(std::move(_t)) { }

protected:
	TypePtr t;
	};

class BaseTypeInfo : public AbstractTypeInfo
	{
public:
	BaseTypeInfo(TypePtr _t) : AbstractTypeInfo(std::move(_t)) { }

	std::string Initializer() const override;
	};

class EnumTypeInfo : public AbstractTypeInfo
	{
public:
	EnumTypeInfo(TypePtr _t) : AbstractTypeInfo(std::move(_t)) { }

	std::string Initializer() const override;
	};

class OpaqueTypeInfo : public AbstractTypeInfo
	{
public:
	OpaqueTypeInfo(TypePtr _t) : AbstractTypeInfo(std::move(_t)) { }

	std::string Initializer() const override;
	};


class CompoundTypeInfo : public AbstractTypeInfo
	{
public:
	CompoundTypeInfo(CPPCompile* _c, TypePtr _t)
		: AbstractTypeInfo(_t), c(_c) { }

protected:
	CPPCompile* c;
	};

class TypeTypeInfo : public CompoundTypeInfo
	{
public:
	TypeTypeInfo(CPPCompile* c, TypePtr _t);

	std::string Initializer() const override;

private:
	TypePtr tt;
	};

class VectorTypeInfo : public CompoundTypeInfo
	{
public:
	VectorTypeInfo(CPPCompile* c, TypePtr _t);

	std::string Initializer() const override;

private:
	TypePtr yield;
	};

class ListTypeInfo : public CompoundTypeInfo
	{
public:
	ListTypeInfo(CPPCompile* c, TypePtr _t);

	std::string Initializer() const override;

private:
	const std::vector<TypePtr>& types;
	};

class TableTypeInfo : public CompoundTypeInfo
	{
public:
	TableTypeInfo(CPPCompile* c, TypePtr _t);

	std::string Initializer() const override;

private:
	int indices;
	TypePtr yield;
	};

class FuncTypeInfo : public CompoundTypeInfo
	{
public:
	FuncTypeInfo(CPPCompile* c, TypePtr _t);

	std::string Initializer() const override;

private:
	FunctionFlavor flavor;
	TypePtr params;
	TypePtr yield;
	};

class RecordTypeInfo : public CompoundTypeInfo
	{
public:
	RecordTypeInfo(CPPCompile* c, TypePtr _t);

	std::string Initializer() const override;

private:
	std::vector<std::string> field_names;
	std::vector<TypePtr> field_types;
	std::vector<int> field_attrs;
	};


	} // zeek::detail
