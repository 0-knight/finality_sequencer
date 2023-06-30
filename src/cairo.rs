use std::{path::Path, env};

use cairo_vm::{types::{program::Program, relocatable::MaybeRelocatable}, vm::{vm_core::VirtualMachine, runners::cairo_runner::CairoRunner}, hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor};

// First of all, compile a cairo program.
// cairo-compile cairo_programs/abs_value_array.cairo --output cairo_programs/abs_value_array_compiled.json

#[test]
pub fn test_run_cario() {

    // Code from https://github.com/lambdaclass/cairo-vm

    let file_path = "./cairo_program/abs_value_array.json";
    // println!("{:?}", env::current_dir());

    // 1. Specify the Cairo program you want to run
    let program = Program::from_file(Path::new(&file_path), None).unwrap();

    // 2. Instantiate the VM, the cairo_runner, the hint processor, and the entrypoint
    let mut vm = VirtualMachine::new(false);
    let mut cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let func_name = "main";
    let entrypoint = program
                                .get_identifier(&format!("__main__.{}", &func_name)).unwrap()
                                .pc
                                .unwrap();
    
    // 3. Lastly, initialize the builtins and segments.
    cairo_runner.initialize_builtins(&mut vm);
    cairo_runner.initialize_segments(&mut vm, None);

    // 4. run
    /*
    pub fn run_from_entrypoint(&mut self, 
            entrypoint: usize, args: &[&CairoArg], verify_secure: bool, 
            program_segment_size: Option<usize>, vm: &mut VirtualMachine, 
            hint_processor: &mut dyn HintProcessor) -> Result<(), CairoRunError>
    */
    let _var = cairo_runner.run_from_entrypoint(
        entrypoint,
        &vec![
                &MaybeRelocatable::from(2).into(),  //this is the entry point selector
                &MaybeRelocatable::from((2,0)).into() //this would be the output_ptr for example if our cairo function uses it
                ],
        false,
        0.into(),
        &mut vm,
        &mut hint_processor,
    );
    println!("{:?}", _var);
}

/*

 let _var = cairo_runner.run_from_entrypoint(
            entrypoint,
            vec![
                &MaybeRelocatable::from(2).into(),  //this is the entry point selector
                &MaybeRelocatable::from((2,0)).into() //this would be the output_ptr for example if our cairo function uses it
                ],
            false,
            &mut vm,
            &mut hint_processor,
        );
 */

